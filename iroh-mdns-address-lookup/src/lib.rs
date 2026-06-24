//! An address lookup service that uses an mdns-like service to discover and lookup the addresses of local endpoints.
//!
//! This allows you to use an mdns-like swarm discovery service to find address information about endpoints that are on your local network, no relay or outside internet needed.
//! See the [`swarm-discovery`](https://crates.io/crates/swarm-discovery) crate for more details.
//!
//! When [`MdnsAddressLookup`] is enabled, it's possible to get a list of the locally discovered endpoints by filtering a list of `RemoteInfo`s.
//!
//! In order to get a list of locally discovered addresses, you must call `MdnsAddressLookup::subscribe` to subscribe
//! to a stream of discovered addresses.
//!
//! ```no_run
//! use iroh::{Endpoint, endpoint::presets};
//! use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
//! use n0_future::StreamExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     let endpoint = Endpoint::bind(presets::Minimal).await.unwrap();
//!
//!     // Register the Address Lookupwith the endpoint
//!     let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
//!     endpoint.address_lookup().unwrap().add(mdns.clone());
//!
//!     // Subscribe to the mdns discovery events
//!     let mut events = mdns.subscribe().await;
//!     while let Some(event) = events.next().await {
//!         match event {
//!             DiscoveryEvent::Discovered { endpoint_info, .. } => {
//!                 println!("MDNS discovered: {:?}", endpoint_info);
//!             }
//!             DiscoveryEvent::Expired { endpoint_id } => {
//!                 println!("MDNS expired: {endpoint_id}");
//!             }
//!             _ => {}
//!         }
//!     }
//! }
//! ```
//!
//! ## Filtering
//!
//! By default, [`MdnsAddressLookup`] publishes all addresses it receives:
//! direct IP addresses and up to one [`RelayUrl`]. The following constraints apply regardless
//! of any user-supplied filter:
//!
//! - Only the first [`RelayUrl`] in the address set is published.
//! - A [`RelayUrl`] longer than 249 bytes is silently dropped.
//!
//! You can supply an [`AddrFilter`] via [`MdnsAddressLookupBuilder::addr_filter`] to
//! control which addresses are published and in what order. The filter is applied before the
//! constraints above, so for example you can use it to exclude relay URLs entirely or to
//! prioritize certain addresses.
//!
//! [`AddrFilter`]: iroh::address_lookup::AddrFilter
//! [`RelayUrl`]: iroh_base::RelayUrl
//!
//! ## Multi-homed hosts
//!
//! Multicast group membership and egress are per network interface. A single
//! wildcard socket only joins the multicast group on the interface of the
//! default route, so on hosts with several network interfaces, mDNS would
//! neither be received from nor sent to the other interfaces.
//!
//! To make discovery work across all local networks a host is attached to,
//! [`MdnsAddressLookup`] watches the host's network interfaces and maintains
//! one multicast socket per usable IPv4 interface (up, non-loopback).
//! Interfaces that appear or disappear at runtime are picked up automatically.
//! If no usable interface is found (or interface watching fails), it falls
//! back to the single wildcard socket.
//!
//! IPv6 multicast currently still uses only the default interface; this is a
//! limitation of the underlying `swarm-discovery` crate.
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, RwLock},
};

// The crate's own watchables and netwatch's interface state watcher both use
// the same `n0_watcher` version that iroh re-exports, so a single `Watcher`
// trait needs to be in scope.
use iroh::Watcher as _;
use iroh::{
    Endpoint,
    address_lookup::{
        AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData,
        EndpointInfo, Error as AddressLookupError, Item as AddressLookupItem,
    },
};
use iroh_base::{EndpointId, PublicKey};
use n0_future::{
    Stream,
    boxed::BoxStream,
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration},
};
use n0_watcher::Watchable;
use swarm_discovery::{Discoverer, DropGuard, IpClass, Peer};
use tokio::sync::mpsc::{self, error::TrySendError};
use tracing::{Instrument, debug, error, info_span, trace, warn};

/// The n0 local service name.
const N0_SERVICE_NAME: &str = "irohv1";

/// Name of this address lookup service.
///
/// Used as the `provenance` field in [`AddressLookupItem`]s.
pub const NAME: &str = "mdns";

/// The key of the attribute under which the `UserData` is stored in
/// the TXT record supported by swarm-discovery.
const USER_DATA_ATTRIBUTE: &str = "user-data";

/// How long we will wait before we stop attempting to resolve an endpoint ID to an address.
const LOOKUP_DURATION: Duration = Duration::from_secs(10);

/// The key of the attribute under which the `RelayUrl` is stored in
/// the TXT record supported by swarm-discovery.
const RELAY_URL_ATTRIBUTE: &str = "relay";

/// Address Lookup using `swarm-discovery`, a variation on mdns.
#[derive(Debug, Clone)]
pub struct MdnsAddressLookup {
    #[allow(dead_code)]
    handle: Arc<AbortOnDropHandle<()>>,
    sender: mpsc::Sender<Message>,
    advertise: bool,
    /// When `local_addrs` changes, we re-publish our info.
    local_addrs: Watchable<Option<EndpointData>>,
    /// IPv4 interface addresses currently used for multicast, kept in sync
    /// with the host's network interfaces by the service task.
    multicast_interfaces: Arc<RwLock<BTreeSet<Ipv4Addr>>>,
}

#[derive(Debug)]
enum Message {
    Discovered(String, Peer),
    Resolve(
        EndpointId,
        mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>,
    ),
    Timeout(EndpointId, usize),
    Subscribe(mpsc::Sender<DiscoveryEvent>),
}

/// Manages the list of subscribers that are subscribed to this Address Lookup.
#[derive(Debug)]
struct Subscribers(Vec<mpsc::Sender<DiscoveryEvent>>);

impl Subscribers {
    fn new() -> Self {
        Self(vec![])
    }

    /// Add the subscriber to the list of subscribers.
    fn push(&mut self, subscriber: mpsc::Sender<DiscoveryEvent>) {
        self.0.push(subscriber);
    }

    /// Sends the `endpoint_id` and `item` to each subscriber.
    ///
    /// Cleans up any subscribers that have been dropped.
    fn send(&mut self, item: DiscoveryEvent) {
        let mut clean_up = vec![];
        for (i, subscriber) in self.0.iter().enumerate() {
            // assume subscriber was dropped
            if let Err(err) = subscriber.try_send(item.clone()) {
                match err {
                    TrySendError::Full(_) => {
                        warn!(?item, idx = i, "mdns subscriber is blocked, dropping item")
                    }
                    TrySendError::Closed(_) => clean_up.push(i),
                }
            }
        }
        for i in clean_up.into_iter().rev() {
            self.0.swap_remove(i);
        }
    }
}

/// Builder for [`MdnsAddressLookup`].
#[derive(Debug)]
pub struct MdnsAddressLookupBuilder {
    advertise: bool,
    service_name: String,
    filter: AddrFilter,
}

impl MdnsAddressLookupBuilder {
    /// Creates a new [`MdnsAddressLookupBuilder`] with default settings.
    fn new() -> Self {
        Self {
            advertise: true,
            service_name: N0_SERVICE_NAME.to_string(),
            filter: AddrFilter::default(),
        }
    }

    /// Sets whether this endpoint should advertise its presence.
    ///
    /// Default is true.
    pub fn advertise(mut self, advertise: bool) -> Self {
        self.advertise = advertise;
        self
    }

    /// Sets a custom service name.
    ///
    /// The default is `irohv1`, which will show up on a record in the
    /// following form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._irohv1._udp.local`
    ///
    /// Any custom service name will take the form, for example:
    /// `7rutqynuzu65fcdgoerbt4uoh3p62wuto2mp56x3uvhitqzssxga._{service_name}._udp.local`
    pub fn service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    /// Sets a filter to control which addresses are published by this service.
    pub fn addr_filter(mut self, filter: AddrFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Builds an [`MdnsAddressLookup`] instance with the configured settings.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    pub fn build(
        self,
        endpoint_id: EndpointId,
    ) -> Result<MdnsAddressLookup, AddressLookupBuilderError> {
        MdnsAddressLookup::new(endpoint_id, self.advertise, self.service_name, self.filter)
    }
}

impl Default for MdnsAddressLookupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressLookupBuilder for MdnsAddressLookupBuilder {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.build(endpoint.id())
    }
}

/// An event emitted from the [`MdnsAddressLookup`] service.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DiscoveryEvent {
    /// A peer was discovered or it's information was updated.
    Discovered {
        /// The endpoint info for the endpoint, as discovered.
        endpoint_info: EndpointInfo,
        /// Optional timestamp when this endpoint address info was last updated.
        last_updated: Option<u64>,
    },
    /// A peer was expired due to being inactive, unreachable, or otherwise
    /// unavailable.
    Expired {
        /// The id of the endpoint that expired.
        endpoint_id: EndpointId,
    },
}

impl MdnsAddressLookup {
    /// Returns a [`MdnsAddressLookupBuilder`] used to construct [`MdnsAddressLookup`].
    pub fn builder() -> MdnsAddressLookupBuilder {
        MdnsAddressLookupBuilder::default()
    }

    /// Create a new [`MdnsAddressLookup`] Service.
    ///
    /// This starts a [`Discoverer`] that broadcasts your addresses (if advertise is set to true)
    /// and receives addresses from other endpoints in your local network.
    ///
    /// # Errors
    /// Returns an error if the network does not allow ipv4 OR ipv6.
    ///
    /// # Panics
    /// This relies on [`tokio::runtime::Handle::current`] and will panic if called outside of the context of a tokio runtime.
    fn new(
        endpoint_id: EndpointId,
        advertise: bool,
        service_name: String,
        filter: AddrFilter,
    ) -> Result<Self, AddressLookupBuilderError> {
        debug!("Creating new Mdns service");
        let (send, mut recv) = mpsc::channel(64);
        let task_sender = send.clone();
        let rt = tokio::runtime::Handle::current();
        let address_lookup = MdnsAddressLookup::spawn_discoverer(
            endpoint_id,
            advertise,
            task_sender.clone(),
            BTreeSet::new(),
            service_name,
            &rt,
        )?;

        let local_addrs: Watchable<Option<EndpointData>> = Watchable::default();
        let mut addrs_change = local_addrs.watch();
        let multicast_interfaces: Arc<RwLock<BTreeSet<Ipv4Addr>>> = Arc::default();
        let multicast_interfaces_task = multicast_interfaces.clone();
        let address_lookup_fut = async move {
            let mut endpoint_addrs: HashMap<PublicKey, Peer> = HashMap::default();
            let mut subscribers = Subscribers::new();
            let mut last_id = 0;
            let mut senders: HashMap<
                PublicKey,
                HashMap<usize, mpsc::Sender<Result<AddressLookupItem, AddressLookupError>>>,
            > = HashMap::default();
            let mut timeouts = JoinSet::new();

            // Maintain one multicast socket per usable IPv4 interface.
            //
            // Multicast group membership and egress are per interface, and
            // without explicit interfaces swarm-discovery operates on a
            // single wildcard socket that only joins the group on the
            // interface of the default route. On multi-homed hosts that
            // makes mDNS invisible on every other interface, and the
            // membership silently moves when the default route changes.
            // The `_monitor` binding keeps the OS route/interface watcher
            // alive for the lifetime of the service task.
            let _monitor = match netwatch::netmon::Monitor::new().await {
                Ok(monitor) => Some(monitor),
                Err(err) => {
                    warn!(
                        "failed to start network monitor, mDNS multicast stays on the default interface only: {err:#}"
                    );
                    None
                }
            };
            let mut interface_state = _monitor.as_ref().map(|m| m.interface_state());
            let mut active_interfaces = BTreeSet::new();
            if let Some(watcher) = interface_state.as_mut() {
                sync_multicast_interfaces(
                    &address_lookup,
                    &mut active_interfaces,
                    multicast_candidate_v4s(&watcher.get()),
                );
                *multicast_interfaces_task.write().expect("poisoned") = active_interfaces.clone();
            }

            loop {
                trace!(?endpoint_addrs, "Mdns Service loop tick");
                let msg = tokio::select! {
                    msg = recv.recv() => {
                        msg
                    }
                    state = async { interface_state.as_mut().expect("guarded by if-branch").updated().await }, if interface_state.is_some() => {
                        match state {
                            Ok(state) => {
                                let desired = multicast_candidate_v4s(&state);
                                if desired != active_interfaces {
                                    sync_multicast_interfaces(
                                        &address_lookup,
                                        &mut active_interfaces,
                                        desired,
                                    );
                                    *multicast_interfaces_task.write().expect("poisoned") =
                                        active_interfaces.clone();
                                }
                            }
                            Err(_) => {
                                warn!("network monitor stopped, mDNS multicast interfaces are no longer updated");
                                interface_state = None;
                            }
                        }
                        continue;
                    }
                    Ok(Some(data)) = addrs_change.updated() => {
                        tracing::trace!(?data, "Mdns address changed");
                        address_lookup.remove_all();

                        // apply user-supplied filter
                        let data = data.apply_filter(&filter).into_owned();


                        let addrs =
                            MdnsAddressLookup::socketaddrs_to_addrs(data.ip_addrs());
                        for addr in addrs {
                            address_lookup.add(addr.0, addr.1)
                        }
                        if let Some(relay) = data.relay_urls().next()
                            && let Err(err) = address_lookup.set_txt_attribute(RELAY_URL_ATTRIBUTE.to_string(), Some(relay.to_string()))  {
                                warn!("Failed to set the relay url in mDNS: {err:?}");
                        }
                        if let Some(user_data) = data.user_data()
                            && let Err(err) = address_lookup.set_txt_attribute(USER_DATA_ATTRIBUTE.to_string(), Some(user_data.to_string())) {
                                warn!("Failed to set the user-defined data in mDNS: {err:?}");
                        }
                        continue;
                    }
                };
                let msg = match msg {
                    None => {
                        error!("Mdns channel closed");
                        error!("closing Mdns");
                        timeouts.abort_all();
                        address_lookup.remove_all();
                        return;
                    }
                    Some(msg) => msg,
                };
                match msg {
                    Message::Discovered(discovered_endpoint_id, peer_info) => {
                        trace!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "Mdns Message::Discovered"
                        );
                        let discovered_endpoint_id =
                            match PublicKey::from_str(&discovered_endpoint_id) {
                                Ok(endpoint_id) => endpoint_id,
                                Err(e) => {
                                    warn!(
                                        discovered_endpoint_id,
                                        "couldn't parse endpoint_id from mdns Address Lookup: {e:?}"
                                    );
                                    continue;
                                }
                            };

                        if discovered_endpoint_id == endpoint_id {
                            continue;
                        }

                        if peer_info.is_expiry() {
                            trace!(
                                ?discovered_endpoint_id,
                                "removing endpoint from Mdns address book"
                            );
                            endpoint_addrs.remove(&discovered_endpoint_id);
                            subscribers.send(DiscoveryEvent::Expired {
                                endpoint_id: discovered_endpoint_id,
                            });
                            continue;
                        }

                        let entry = endpoint_addrs.entry(discovered_endpoint_id);
                        if let std::collections::hash_map::Entry::Occupied(ref entry) = entry
                            && peer_content_eq(entry.get(), &peer_info)
                        {
                            // this is a republish we already know about
                            continue;
                        }

                        debug!(
                            ?discovered_endpoint_id,
                            ?peer_info,
                            "adding endpoint to Mdns address book"
                        );

                        let mut resolved = false;
                        let item = peer_to_discovery_item(&peer_info, &discovered_endpoint_id);
                        if let Some(senders) = senders.get(&discovered_endpoint_id) {
                            trace!(?item, senders = senders.len(), "sending AddressLookupItem");
                            resolved = true;
                            for sender in senders.values() {
                                sender.send(Ok(item.clone())).await.ok();
                            }
                        }
                        entry.or_insert(peer_info);

                        // only send endpoints to the `subscriber` if they weren't explicitly resolved
                        // in other words, endpoints sent to the `subscribers` should only be the ones that
                        // have been "passively" discovered
                        if !resolved {
                            subscribers.send(DiscoveryEvent::Discovered {
                                endpoint_info: item.endpoint_info().clone(),
                                last_updated: item.last_updated(),
                            });
                        }
                    }
                    Message::Resolve(endpoint_id, sender) => {
                        let id = last_id + 1;
                        last_id = id;
                        trace!(?endpoint_id, "Mdns Message::SendAddrs");
                        if let Some(peer_info) = endpoint_addrs.get(&endpoint_id) {
                            let item = peer_to_discovery_item(peer_info, &endpoint_id);
                            debug!(?item, "sending AddressLookupItem");
                            sender.send(Ok(item)).await.ok();
                        }
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.insert(id, sender);
                        } else {
                            let mut senders_for_endpoint_id = HashMap::new();
                            senders_for_endpoint_id.insert(id, sender);
                            senders.insert(endpoint_id, senders_for_endpoint_id);
                        }
                        let timeout_sender = task_sender.clone();
                        timeouts.spawn(async move {
                            time::sleep(LOOKUP_DURATION).await;
                            trace!(?endpoint_id, "resolution timeout");
                            timeout_sender
                                .send(Message::Timeout(endpoint_id, id))
                                .await
                                .ok();
                        });
                    }
                    Message::Timeout(endpoint_id, id) => {
                        trace!(?endpoint_id, "Mdns Message::Timeout");
                        if let Some(senders_for_endpoint_id) = senders.get_mut(&endpoint_id) {
                            senders_for_endpoint_id.remove(&id);
                            if senders_for_endpoint_id.is_empty() {
                                senders.remove(&endpoint_id);
                            }
                        }
                    }
                    Message::Subscribe(subscriber) => {
                        trace!("Mdns Message::Subscribe");
                        subscribers.push(subscriber);
                    }
                }
            }
        };
        let handle =
            task::spawn(address_lookup_fut.instrument(info_span!("swarm-discovery.actor")));
        Ok(Self {
            handle: Arc::new(AbortOnDropHandle::new(handle)),
            sender: send,
            advertise,
            local_addrs,
            multicast_interfaces,
        })
    }

    /// Returns the IPv4 interface addresses currently used for multicast.
    ///
    /// Primarily useful for diagnostics. The set is empty until the network
    /// monitor has reported the initial interface state, and stays empty when
    /// the host has no usable non-loopback IPv4 interface; in both cases
    /// swarm-discovery operates on a single wildcard socket bound to the
    /// default interface.
    pub fn multicast_interfaces(&self) -> BTreeSet<Ipv4Addr> {
        self.multicast_interfaces.read().expect("poisoned").clone()
    }

    /// Subscribe to discovered endpoints.
    pub async fn subscribe(&self) -> impl Stream<Item = DiscoveryEvent> + Unpin + use<> {
        let (sender, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        address_lookup_sender
            .send(Message::Subscribe(sender))
            .await
            .ok();
        tokio_stream::wrappers::ReceiverStream::new(recv)
    }

    fn spawn_discoverer(
        endpoint_id: PublicKey,
        advertise: bool,
        sender: mpsc::Sender<Message>,
        socketaddrs: BTreeSet<SocketAddr>,
        service_name: String,
        rt: &tokio::runtime::Handle,
    ) -> Result<DropGuard, AddressLookupBuilderError> {
        let spawn_rt = rt.clone();
        let callback = move |endpoint_id: &str, peer: &Peer| {
            trace!(endpoint_id, ?peer, "Received peer information from Mdns");

            let sender = sender.clone();
            let endpoint_id = endpoint_id.to_string();
            let peer = peer.clone();
            spawn_rt.spawn(async move {
                sender
                    .send(Message::Discovered(endpoint_id, peer))
                    .await
                    .ok();
            });
        };
        let endpoint_id_str = data_encoding::BASE32_NOPAD
            .encode(endpoint_id.as_bytes())
            .to_ascii_lowercase();
        let mut discoverer = Discoverer::new_interactive(service_name, endpoint_id_str)
            .with_callback(callback)
            .with_ip_class(IpClass::Auto);
        if advertise {
            let addrs = MdnsAddressLookup::socketaddrs_to_addrs(socketaddrs.iter());
            for addr in addrs {
                discoverer = discoverer.with_addrs(addr.0, addr.1);
            }
        }
        discoverer
            .spawn(rt)
            .map_err(|e| AddressLookupBuilderError::from_err("mdns", e))
    }

    fn socketaddrs_to_addrs<'a>(
        socketaddrs: impl Iterator<Item = &'a SocketAddr>,
    ) -> HashMap<u16, Vec<IpAddr>> {
        let mut addrs: HashMap<u16, Vec<IpAddr>> = HashMap::default();
        for socketaddr in socketaddrs {
            addrs
                .entry(socketaddr.port())
                .and_modify(|a| a.push(socketaddr.ip()))
                .or_insert(vec![socketaddr.ip()]);
        }
        addrs
    }
}

/// Returns true if two peer snapshots carry the same announcement content,
/// meaning the same addresses and TXT attributes.
///
/// `Peer`'s derived equality also compares the last-seen timestamp, which
/// differs between copies of the same announcement, for example when it is
/// received on several interfaces. Comparing content only ensures duplicate
/// copies are recognized as the republish they are, instead of producing a
/// stream of repeated discovery events.
fn peer_content_eq(a: &Peer, b: &Peer) -> bool {
    a.addrs() == b.addrs() && a.txt_attributes().eq(b.txt_attributes())
}

/// Returns the IPv4 addresses of all interfaces that should carry mDNS
/// multicast, based on the current interface state.
fn multicast_candidate_v4s(state: &netwatch::interfaces::State) -> BTreeSet<Ipv4Addr> {
    filter_multicast_candidate_v4s(
        state
            .interfaces
            .values()
            .map(|iface| (iface.is_up(), iface.addrs().map(|net| net.addr()))),
    )
}

/// Filters interface addresses down to the IPv4 addresses usable for
/// multicast: the interface must be up, and loopback, unspecified, and
/// broadcast addresses are skipped.
///
/// Loopback is excluded because the wildcard socket already covers
/// same-host discovery via multicast loopback on the egress interface.
fn filter_multicast_candidate_v4s<I, A>(interfaces: I) -> BTreeSet<Ipv4Addr>
where
    I: IntoIterator<Item = (bool, A)>,
    A: IntoIterator<Item = IpAddr>,
{
    let mut out = BTreeSet::new();
    for (is_up, addrs) in interfaces {
        if !is_up {
            continue;
        }
        for addr in addrs {
            if let IpAddr::V4(addr) = addr
                && !addr.is_loopback()
                && !addr.is_unspecified()
                && !addr.is_broadcast()
            {
                out.insert(addr);
            }
        }
    }
    out
}

/// Brings the swarm-discovery multicast sockets in sync with `desired`,
/// adding sockets for new interfaces and removing sockets for interfaces
/// that disappeared. Updates `active` to the desired set.
///
/// Socket creation happens asynchronously inside swarm-discovery and
/// failures are only logged there (for example when an interface vanishes
/// between observation and socket creation). `active` therefore tracks the
/// desired state, which self-corrects on the next interface change.
fn sync_multicast_interfaces(
    guard: &DropGuard,
    active: &mut BTreeSet<Ipv4Addr>,
    desired: BTreeSet<Ipv4Addr>,
) {
    for addr in desired.difference(active) {
        debug!(%addr, "adding interface to mDNS multicast");
        guard.add_interface_v4(*addr);
    }
    for addr in active.difference(&desired) {
        debug!(%addr, "removing interface from mDNS multicast");
        guard.remove_interface_v4(*addr);
    }
    *active = desired;
}

fn peer_to_discovery_item(peer: &Peer, endpoint_id: &EndpointId) -> AddressLookupItem {
    let ip_addrs: BTreeSet<SocketAddr> = peer
        .addrs()
        .iter()
        .map(|(ip, port)| SocketAddr::new(*ip, *port))
        .collect();

    // Get the relay url from the resolved peer info. We expect an attribute that parses as
    // a `RelayUrl`. Otherwise, omit.
    let relay_url = if let Some(Some(relay_url)) = peer.txt_attribute(RELAY_URL_ATTRIBUTE) {
        match relay_url.parse() {
            Err(err) => {
                debug!("failed to parse relay url from TXT attribute: {err}");
                None
            }
            Ok(url) => Some(url),
        }
    } else {
        None
    };

    // Get the user-defined data from the resolved peer info. We expect an attribute with a value
    // that parses as `UserData`. Otherwise, omit.
    let user_data = if let Some(Some(user_data)) = peer.txt_attribute(USER_DATA_ATTRIBUTE) {
        match user_data.parse() {
            Err(err) => {
                debug!("failed to parse user data from TXT attribute: {err}");
                None
            }
            Ok(data) => Some(data),
        }
    } else {
        None
    };

    let mut data = EndpointData::from(ip_addrs);
    if let Some(relay_url) = relay_url {
        data.add_relay_url(relay_url);
    }
    data.set_user_data(user_data);

    let endpoint_info = EndpointInfo::from_parts(*endpoint_id, data);
    AddressLookupItem::new(endpoint_info, NAME, None)
}

impl AddressLookup for MdnsAddressLookup {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<BoxStream<Result<AddressLookupItem, AddressLookupError>>> {
        use futures_util::FutureExt;

        let (send, recv) = mpsc::channel(20);
        let address_lookup_sender = self.sender.clone();
        let stream = async move {
            address_lookup_sender
                .send(Message::Resolve(endpoint_id, send))
                .await
                .ok();
            tokio_stream::wrappers::ReceiverStream::new(recv)
        };
        Some(Box::pin(stream.flatten_stream()))
    }

    fn publish(&self, data: &EndpointData) {
        if self.advertise {
            self.local_addrs.set(Some(data.clone())).ok();
        }
    }
}

#[cfg(test)]
mod tests {

    /// Pure unit tests that do not open sockets, safe to run concurrently.
    mod unit {
        use std::net::Ipv6Addr;

        use super::super::*;

        fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }

        #[test]
        fn filter_keeps_usable_ipv4_of_up_interfaces() {
            let got = filter_multicast_candidate_v4s([
                (true, vec![v4(192, 168, 1, 2)]),
                (true, vec![v4(10, 0, 0, 7), v4(172, 16, 0, 1)]),
            ]);
            let expected: BTreeSet<Ipv4Addr> = [
                Ipv4Addr::new(192, 168, 1, 2),
                Ipv4Addr::new(10, 0, 0, 7),
                Ipv4Addr::new(172, 16, 0, 1),
            ]
            .into();
            assert_eq!(got, expected);
        }

        #[test]
        fn filter_skips_down_interfaces() {
            let got = filter_multicast_candidate_v4s([
                (false, vec![v4(192, 168, 1, 2)]),
                (true, vec![v4(10, 0, 0, 7)]),
            ]);
            assert_eq!(got, BTreeSet::from([Ipv4Addr::new(10, 0, 0, 7)]));
        }

        #[test]
        fn filter_skips_loopback_unspecified_and_broadcast() {
            let got = filter_multicast_candidate_v4s([(
                true,
                vec![
                    v4(127, 0, 0, 1),
                    v4(0, 0, 0, 0),
                    v4(255, 255, 255, 255),
                    v4(192, 168, 1, 2),
                ],
            )]);
            assert_eq!(got, BTreeSet::from([Ipv4Addr::new(192, 168, 1, 2)]));
        }

        #[test]
        fn filter_skips_ipv6() {
            let got = filter_multicast_candidate_v4s([(
                true,
                vec![
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    v4(192, 168, 1, 2),
                ],
            )]);
            assert_eq!(got, BTreeSet::from([Ipv4Addr::new(192, 168, 1, 2)]));
        }

        #[test]
        fn filter_dedups_addresses_shared_by_interfaces() {
            let got = filter_multicast_candidate_v4s([
                (true, vec![v4(192, 168, 1, 2)]),
                (true, vec![v4(192, 168, 1, 2)]),
            ]);
            assert_eq!(got, BTreeSet::from([Ipv4Addr::new(192, 168, 1, 2)]));
        }

        #[test]
        fn filter_empty_input_yields_empty_set() {
            let got = filter_multicast_candidate_v4s(Vec::<(bool, Vec<IpAddr>)>::new());
            assert!(got.is_empty());
        }

        #[test]
        fn candidates_from_interface_state() {
            let state = netwatch::interfaces::State::fake();
            // The fake state contains one up interface with 192.168.0.189.
            assert_eq!(
                multicast_candidate_v4s(&state),
                BTreeSet::from([Ipv4Addr::new(192, 168, 0, 189)])
            );
        }

        #[test]
        fn candidates_from_state_without_interfaces() {
            let mut state = netwatch::interfaces::State::fake();
            state.interfaces.clear();
            assert!(multicast_candidate_v4s(&state).is_empty());
        }
    }

    /// This module's name signals nextest to run test in a single thread (no other concurrent
    /// tests).
    mod run_in_isolation {
        use iroh::endpoint_info::UserData;
        use iroh_base::{SecretKey, TransportAddr};
        use n0_error::{AnyError as Error, Result, StdResultExt, bail_any};
        use n0_future::StreamExt;
        use n0_tracing_test::traced_test;
        use rand::{CryptoRng, RngExt, SeedableRng};

        use super::super::*;

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_resolve() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create Address LookupA with advertise=false (only listens)
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            // Create Address LookupB with advertise=true (will broadcast)
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // make addr info for discoverer b
            let user_data: UserData = "foobar".parse()?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data(user_data.clone());

            // resolve twice to ensure we can create separate streams for the same endpoint_id
            let mut s1 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });
            let mut s2 = address_lookup_a
                .subscribe()
                .await
                .filter(|event| match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        endpoint_info.endpoint_id == endpoint_id_b
                    }
                    _ => false,
                });

            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");
            // publish address_lookup_b's address
            address_lookup_b.publish(&endpoint_data);
            let DiscoveryEvent::Discovered {
                endpoint_info: s1_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s1.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            let DiscoveryEvent::Discovered {
                endpoint_info: s2_endpoint_info,
                ..
            } = tokio::time::timeout(Duration::from_secs(5), s2.next())
                .await
                .std_context("timeout")?
                .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };
            assert_eq!(s1_endpoint_info.data, endpoint_data);
            assert_eq!(s2_endpoint_info.data, endpoint_data);

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_expire() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            // publish address_lookup_b's address
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())])
                    .with_user_data("".parse()?);
            address_lookup_b.publish(&endpoint_data);

            let mut s1 = address_lookup_a.subscribe().await;
            tracing::debug!(?endpoint_id_b, "Discovering endpoint id b");

            // Wait for the specific endpoint to be discovered
            loop {
                let event = tokio::time::timeout(Duration::from_secs(5), s1.next())
                    .await
                    .std_context("timeout")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. }
                        if endpoint_info.endpoint_id == endpoint_id_b =>
                    {
                        break;
                    }
                    _ => continue, // Ignore other discovery events
                }
            }

            // Shutdown endpoint B
            drop(address_lookup_b);
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Wait for the expiration event for the specific endpoint
            loop {
                let event = tokio::time::timeout(Duration::from_secs(10), s1.next())
                    .await
                    .std_context("timeout waiting for expiration event")?
                    .expect("Stream should not be closed");

                match event {
                    DiscoveryEvent::Expired {
                        endpoint_id: expired_endpoint_id,
                    } if expired_endpoint_id == endpoint_id_b => {
                        break;
                    }
                    _ => continue, // Ignore other events
                }
            }

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_subscribe() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let num_endpoints = 5;
            let mut endpoint_ids = BTreeSet::new();
            let mut address_lookup_list = vec![];

            let (_, address_lookup) = make_address_lookup(&mut rng, false)?;
            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);

            for i in 0..num_endpoints {
                let (endpoint_id, address_lookup) = make_address_lookup(&mut rng, true)?;
                let user_data: UserData = format!("endpoint{i}").parse()?;
                let endpoint_data = endpoint_data.clone().with_user_data(user_data.clone());
                endpoint_ids.insert((endpoint_id, Some(user_data)));
                address_lookup.publish(&endpoint_data);
                address_lookup_list.push(address_lookup);
            }

            let mut events = address_lookup.subscribe().await;

            let test = async move {
                let mut got_ids = BTreeSet::new();
                while got_ids.len() != num_endpoints {
                    if let Some(DiscoveryEvent::Discovered { endpoint_info, .. }) =
                        events.next().await
                    {
                        let data = endpoint_info.data.user_data().cloned();
                        if endpoint_ids.contains(&(endpoint_info.endpoint_id, data.clone())) {
                            got_ids.insert((endpoint_info.endpoint_id, data));
                        }
                    } else {
                        bail_any!(
                            "no more events, only got {} ids, expected {num_endpoints}\n",
                            got_ids.len()
                        );
                    }
                }
                assert_eq!(got_ids, endpoint_ids);
                Ok::<_, Error>(())
            };
            tokio::time::timeout(Duration::from_secs(5), test)
                .await
                .std_context("timeout")?
        }

        #[tokio::test]
        #[traced_test]
        async fn non_advertising_endpoint_not_discovered() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, false)?;

            let (endpoint_id_c, address_lookup_c) = make_address_lookup(&mut rng, true)?;
            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let mut stream_c = address_lookup_a.resolve(endpoint_id_c).unwrap();
            let result_c = tokio::time::timeout(Duration::from_secs(2), stream_c.next()).await;
            assert!(
                result_c.is_ok(),
                "Advertising endpoint should be discoverable"
            );

            let mut stream_b = address_lookup_a.resolve(endpoint_id_b).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Expected timeout since endpoint b isn't advertising"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn test_service_names() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an Address Lookupusing the default
            // service name
            let id_a = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_a = MdnsAddressLookup::builder().build(id_a)?;

            // Create a Address Lookupusing a custom
            // service name
            let id_b = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_b = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_b)?;

            // Create an Address Lookupusing the same
            // custom service name
            let id_c = SecretKey::from_bytes(&rng.random()).public();
            let address_lookup_c = MdnsAddressLookup::builder()
                .service_name("different.name")
                .build(id_c)?;

            let endpoint_data_a =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_a.publish(&endpoint_data_a);

            let endpoint_data_b =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:22222".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data_b);

            let endpoint_data_c =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:33333".parse().unwrap())]);
            address_lookup_c.publish(&endpoint_data_c);

            let mut stream_a = address_lookup_a.resolve(id_b).unwrap();
            let result_a = tokio::time::timeout(Duration::from_secs(2), stream_a.next()).await;
            assert!(
                result_a.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_c).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_ok(),
                "Endpoint on the same service should be discoverable"
            );

            let mut stream_b = address_lookup_b.resolve(id_a).unwrap();
            let result_b = tokio::time::timeout(Duration::from_secs(2), stream_b.next()).await;
            assert!(
                result_b.is_err(),
                "Endpoint on a different service should NOT be discoverable"
            );

            Ok(())
        }

        #[tokio::test]
        #[traced_test]
        async fn mdns_publish_relay_url() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            // Create an mdns address lookup A that only listens
            let (_, mdns_a) = make_address_lookup(&mut rng, false)?;

            // Create an mdns address lookup B that includes a relay url for publishing
            let (endpoint_id_b, mdns_b) = make_address_lookup(&mut rng, true)?;
            let relay_url: iroh_base::RelayUrl = "https://relay.example.com".parse().unwrap();
            let endpoint_data = EndpointData::from_iter([
                TransportAddr::Ip("0.0.0.0:11111".parse().unwrap()),
                TransportAddr::Relay(relay_url.clone()),
            ]);

            // Subscribe to discovery events filtered for endpoint B
            let mut events = mdns_a.subscribe().await.filter(|event| match event {
                DiscoveryEvent::Discovered { endpoint_info, .. } => {
                    endpoint_info.endpoint_id == endpoint_id_b
                }
                _ => false,
            });

            // Publish mdns_b's address with relay URL
            mdns_b.publish(&endpoint_data);

            // Wait for discovery
            let DiscoveryEvent::Discovered { endpoint_info, .. } =
                tokio::time::timeout(Duration::from_secs(2), events.next())
                    .await
                    .std_context("timeout")?
                    .unwrap()
            else {
                panic!("Received unexpected discovery event");
            };

            // Verify the relay URL was received
            let discovered_relay_urls: Vec<_> = endpoint_info.data.relay_urls().collect();
            assert_eq!(discovered_relay_urls.len(), 1);
            assert_eq!(discovered_relay_urls[0], &relay_url);

            Ok(())
        }

        /// The service task must converge `multicast_interfaces()` to the
        /// host's current usable IPv4 interfaces (which may be empty, in
        /// which case the wildcard-socket fallback is active).
        #[tokio::test]
        #[traced_test]
        async fn multicast_interfaces_match_host_state() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
            let (_, address_lookup) = make_address_lookup(&mut rng, true)?;

            let expected = multicast_candidate_v4s(&netwatch::interfaces::State::new().await);
            let converge = async {
                while address_lookup.multicast_interfaces() != expected {
                    time::sleep(Duration::from_millis(50)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(5), converge)
                .await
                .std_context("multicast interfaces did not converge to host state")?;
            assert_eq!(address_lookup.multicast_interfaces(), expected);
            Ok(())
        }

        /// Republished announcements with unchanged content must not produce
        /// repeated `Discovered` events. The same announcement is received
        /// multiple times: as responses to repeated queries, and once per
        /// interface on multi-homed hosts. Without content-based
        /// deduplication these copies flood subscribers and can drown out
        /// other events.
        #[tokio::test]
        #[traced_test]
        async fn republished_info_yields_single_discovery_event() -> Result {
            let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);

            let (_, address_lookup_a) = make_address_lookup(&mut rng, false)?;
            let (endpoint_id_b, address_lookup_b) = make_address_lookup(&mut rng, true)?;

            let endpoint_data =
                EndpointData::from_iter([TransportAddr::Ip("0.0.0.0:11111".parse().unwrap())]);
            address_lookup_b.publish(&endpoint_data);

            let mut events = address_lookup_a.subscribe().await;

            // Wait for the first Discovered event for endpoint B. Other
            // endpoints on the local network may surface here as well.
            let first = async {
                loop {
                    match events.next().await {
                        Some(DiscoveryEvent::Discovered { endpoint_info, .. })
                            if endpoint_info.endpoint_id == endpoint_id_b =>
                        {
                            return Ok::<_, Error>(());
                        }
                        Some(_) => continue,
                        None => bail_any!("event stream ended unexpectedly"),
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(5), first)
                .await
                .std_context("timeout waiting for first discovery")??;

            // Observe for a while: endpoint B keeps answering queries with
            // the same content, so no further Discovered event may arrive.
            let observe = async {
                while let Some(event) = events.next().await {
                    if let DiscoveryEvent::Discovered { endpoint_info, .. } = event
                        && endpoint_info.endpoint_id == endpoint_id_b
                    {
                        bail_any!("received duplicate Discovered event for unchanged content");
                    }
                }
                Ok(())
            };
            match tokio::time::timeout(Duration::from_secs(3), observe).await {
                // Timeout means no duplicate arrived, which is what we want.
                Err(_) => Ok(()),
                Ok(result) => result,
            }
        }

        fn make_address_lookup<R: CryptoRng + ?Sized>(
            rng: &mut R,
            advertise: bool,
        ) -> Result<(PublicKey, MdnsAddressLookup)> {
            let endpoint_id = SecretKey::from_bytes(&rng.random()).public();
            Ok((
                endpoint_id,
                MdnsAddressLookup::builder()
                    .advertise(advertise)
                    .build(endpoint_id)?,
            ))
        }
    }
}
