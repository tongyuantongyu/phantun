use clap::{crate_version, Arg, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::{Socket, Stack};
use log::{debug, error, info, warn};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport, udp_recv_pktinfo};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, Notify, RwLock};
use tokio::time::{self, Duration};
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[derive(Debug, Clone)]
struct ClientConfig {
    name: String,
    local: SocketAddr,
    remote: SocketAddr,
}

impl ClientConfig {
    fn parse_from_file(name: String, content: &str) -> Result<Self, String> {
        let parts: Vec<&str> = content.split_whitespace().collect();

        if parts.len() != 2 {
            return Err(format!(
                "Expected 2 values (local and remote), found {}",
                parts.len()
            ));
        }

        let local = parts[0]
            .parse()
            .map_err(|e| format!("Failed to parse local address '{}': {}", parts[0], e))?;

        let remote = parts[1]
            .parse()
            .map_err(|e| format!("Failed to parse remote address '{}': {}", parts[1], e))?;

        Ok(ClientConfig {
            name,
            local,
            remote,
        })
    }
}

struct ClientInstance {
    config: ClientConfig,
    cancel_token: CancellationToken,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Client Daemon")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("watch_dir")
                .short('w')
                .long("watch-dir")
                .required(false)
                .value_name("PATH")
                .help("Directory to watch for client configuration files")
                .default_value("/run/phantun/clients/"),
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value(""),
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1"),
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Phantun Client's end)")
                .default_value("192.168.200.2"),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1"),
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end)")
                .default_value("fcc8::2"),
        )
        .get_matches();

    let watch_dir = PathBuf::from(matches.get_one::<String>("watch_dir").unwrap());
    let tun_name = matches.get_one::<String>("tun").unwrap().to_string();
    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");
    let tun_local6: Option<std::net::Ipv6Addr> = matches
        .get_one::<String>("tun_local6")
        .map(|v| v.parse().expect("bad local IPv6 address for Tun interface"));
    let tun_peer6: Option<std::net::Ipv6Addr> = matches
        .get_one::<String>("tun_peer6")
        .map(|v| v.parse().expect("bad peer IPv6 address for Tun interface"));

    info!("Phantun Client Daemon starting...");
    info!("Watching directory: {}", watch_dir.display());

    // Create watch directory if it doesn't exist
    if !watch_dir.exists() {
        fs::create_dir_all(&watch_dir)?;
        info!("Created watch directory: {}", watch_dir.display());
    }

    // Create TUN interface ONCE for all clients
    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(&tun_name)
        .up()
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to create TUN device: {}", e),
            )
        })?;

    // Assign IPv6 if needed (check if any configuration will need it)
    if let (Some(local6), Some(peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), local6, peer6);
        info!("Assigned IPv6 addresses to TUN device");
    }

    info!("Created TUN device {}", tun[0].name());

    // Create the shared Stack for all clients
    let stack = Arc::new(RwLock::new(Stack::new(tun, tun_peer, tun_peer6)));

    let clients = Arc::new(RwLock::new(HashMap::<String, ClientInstance>::new()));

    // Setup file watcher
    let (tx, mut rx) = mpsc::channel(100);

    let mut watcher = RecommendedWatcher::new(
        move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        },
        Config::default(),
    )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to create watcher: {}", e)))?;

    watcher
        .watch(&watch_dir, RecursiveMode::NonRecursive)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to watch directory: {}", e)))?;

    info!("File watcher initialized successfully");

    // Do initial scan
    if let Err(e) = process_directory(&watch_dir, &clients, &stack).await {
        error!("Initial directory scan failed: {}", e);
    }

    // Process file system events
    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                        debug!("File system event: {:?}", event);
                        if let Err(e) = process_directory(&watch_dir, &clients, &stack).await {
                            error!("Failed to process directory changes: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn process_directory(
    watch_dir: &Path,
    clients: &Arc<RwLock<HashMap<String, ClientInstance>>>,
    stack: &Arc<RwLock<Stack>>,
) -> io::Result<()> {
    let current_files = scan_directory(watch_dir).await?;

    let mut clients_lock = clients.write().await;

    // Remove clients whose files no longer exist
    let mut to_remove = Vec::new();
    for (name, instance) in clients_lock.iter() {
        if !current_files.contains_key(name) {
            info!("Configuration file for client '{}' removed, stopping client", name);
            instance.cancel_token.cancel();
            to_remove.push(name.clone());
        }
    }
    for name in to_remove {
        clients_lock.remove(&name);
    }

    // Add or restart clients for new/changed files
    for (name, path) in current_files {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to read file {}: {}", path.display(), e);
                continue;
            }
        };

        let config = match ClientConfig::parse_from_file(name.clone(), &content) {
            Ok(c) => c,
            Err(e) => {
                error!("Invalid configuration in file {}: {}", path.display(), e);
                continue;
            }
        };

        // Check if client already exists with same config
        if let Some(existing) = clients_lock.get(&name) {
            if existing.config.local == config.local
                && existing.config.remote == config.remote
            {
                // Configuration unchanged, skip
                continue;
            }

            // Configuration changed, stop old client
            info!(
                "Configuration for client '{}' changed, restarting",
                name
            );
            existing.cancel_token.cancel();
            clients_lock.remove(&name);
        }

        // Start new client
        info!(
            "Starting client '{}': local={}, remote={}",
            config.name, config.local, config.remote
        );

        let cancel_token = CancellationToken::new();
        let client_cancel = cancel_token.clone();

        let client_config = config.clone();
        let stack_clone = stack.clone();

        tokio::spawn(async move {
            if let Err(e) = run_client(
                client_config,
                stack_clone,
                client_cancel,
            )
                .await
            {
                error!("Client '{}' error: {}", client_config.name, e);
            }
        });

        clients_lock.insert(
            name.clone(),
            ClientInstance {
                config,
                cancel_token,
            },
        );
    }

    Ok(())
}

async fn scan_directory(dir: &Path) -> io::Result<HashMap<String, PathBuf>> {
    let mut files = HashMap::new();

    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                files.insert(name.to_string(), path);
            }
        }
    }

    Ok(files)
}

async fn run_client(
    config: ClientConfig,
    stack: Arc<RwLock<Stack>>,
    cancel_token: CancellationToken,
) -> io::Result<()> {
    let client_name = config.name.clone();
    let local_addr = config.local;
    let remote_addr = config.remote;

    info!(
        "Client '{}': Starting with local={}, remote={}",
        client_name, local_addr, remote_addr
    );

    let udp_sock = Arc::new(new_udp_reuseport(local_addr));
    let connections = Arc::new(RwLock::new(HashMap::<SocketAddr, Arc<Socket>>::new()));
    let num_cpus = num_cpus::get();

    let mut buf_r = [0u8; MAX_PACKET_LEN];

    loop {
        tokio::select! {
            result = udp_recv_pktinfo(&udp_sock, &mut buf_r) => {
                let (size, udp_remote_addr, udp_local_addr) = result?;

                if let Some(sock) = connections.read().await.get(&udp_remote_addr) {
                    sock.send(&buf_r[..size]).await;
                    continue;
                }

                info!("Client '{}': New UDP client from {}", client_name, udp_remote_addr);

                // Connect using the shared stack
                let sock = {
                    let mut stack_lock = stack.write().await;
                    stack_lock.connect(remote_addr).await
                };

                if sock.is_none() {
                    error!("Client '{}': Unable to connect to remote {}", client_name, remote_addr);
                    continue;
                }

                let sock = Arc::new(sock.unwrap());

                if sock.send(&buf_r[..size]).await.is_none() {
                    continue;
                }

                assert!(connections
                    .write()
                    .await
                    .insert(udp_remote_addr, sock.clone())
                    .is_none());
                debug!("Client '{}': inserted fake TCP socket into connection table", client_name);

                let packet_received = Arc::new(Notify::new());
                let quit = CancellationToken::new();

                tokio::spawn(async move {
                    let mut buf_udp = [0u8; MAX_PACKET_LEN];
                    let mut buf_tcp = [0u8; MAX_PACKET_LEN];

                    let bind_addr = match (udp_remote_addr, udp_local_addr) {
                        (SocketAddr::V4(_), IpAddr::V4(udp_local_ipv4)) => {
                            SocketAddr::V4(SocketAddrV4::new(
                                udp_local_ipv4,
                                local_addr.port(),
                            ))
                        }
                        (SocketAddr::V6(udp_remote_addr), IpAddr::V6(udp_local_ipv6)) => {
                            SocketAddr::V6(SocketAddrV6::new(
                                udp_local_ipv6,
                                local_addr.port(),
                                udp_remote_addr.flowinfo(),
                                udp_remote_addr.scope_id(),
                            ))
                        }
                        (_, _) => {
                            panic!("Client '{}': unexpected family combination for udp_remote_addr={udp_remote_addr} and udp_local_addr={udp_local_addr}", client_name);
                        }
                    };
                    let udp_sock = new_udp_reuseport(bind_addr);
                    udp_sock.connect(udp_remote_addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                if sock.send(&buf_udp[..size]).await.is_none() {
                                    debug!("Client '{}': removed fake TCP socket from connections table", client_name);
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0
                                            && let Err(e) = udp_sock.send(&buf_tcp[..size]).await {
                                                error!("Client '{}': Unable to send UDP packet to {}: {}, closing connection", client_name, remote_addr, e);
                                                quit.cancel();
                                                return;
                                            }
                                    },
                                    None => {
                                        debug!("Client '{}': removed fake TCP socket from connections table", client_name);
                                        quit.cancel();
                                        return;
                                    },
                                }

                                packet_received.notify_one();
                            },
                            _ = quit.cancelled() => {
                                debug!("Client '{}': worker terminated", client_name);
                                return;
                            },
                        }
                    }
                });

                let connections_clone = connections.clone();
                let timeout_name = client_name.clone();
                tokio::spawn(async move {
                    loop {
                        let read_timeout = time::sleep(UDP_TTL);
                        let packet_received_fut = packet_received.notified();

                        tokio::select! {
                            _ = read_timeout => {
                                info!("Client '{}': No traffic seen in the last {:?}, closing connection", timeout_name, UDP_TTL);
                                connections_clone.write().await.remove(&udp_remote_addr);
                                debug!("Client '{}': removed fake TCP socket from connections table", timeout_name);

                                quit.cancel();
                                return;
                            },
                            _ = quit.cancelled() => {
                                connections_clone.write().await.remove(&udp_remote_addr);
                                debug!("Client '{}': removed fake TCP socket from connections table", timeout_name);
                                return;
                            },
                            _ = packet_received_fut => {},
                        }
                    }
                });
            },
            _ = cancel_token.cancelled() => {
                info!("Client '{}': shutting down", client_name);
                return Ok(());
            }
        }
    }
}