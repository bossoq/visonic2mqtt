#![recursion_limit = "256"]
mod mqtt;
mod visonic;

use log::{error, info};
use mqtt::{
    parse_payload, publish_discovery, publish_state, setup as mqtt_setup, MQTT_CONFIG, QOS,
};
use std::{env::var, sync::LazyLock, time::Duration};
use tokio::{sync::Mutex, time};
use visonic::{System, SystemStatus};

static REFRESH_INTERVAL: LazyLock<u64> = LazyLock::new(|| {
    var("REFRESH_INTERVAL")
        .unwrap_or("10".to_string())
        .parse()
        .unwrap_or(10)
});
static MQTT_PUBLISH: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));
static MQTT_CLIENT: LazyLock<Mutex<Option<rumqttc::AsyncClient>>> =
    LazyLock::new(|| Mutex::new(None));
static ALARM_SYSTEM: LazyLock<Mutex<Option<System>>> = LazyLock::new(|| Mutex::new(None));
static ALARM_SYSTEM_STATUS: LazyLock<Mutex<SystemStatus>> =
    LazyLock::new(|| Mutex::new(SystemStatus::default()));

#[tokio::main]
pub async fn run() {
    let (main_client, mut eventloop) = mqtt_setup().await.unwrap();
    *MQTT_CLIENT.lock().await = Some(main_client);
    setup().await;
    let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
    let model = alarm_status_lock.model().to_lowercase();
    let serial = alarm_status_lock.serial_number().to_lowercase();
    let topic_prefix = format!("{}/{}_{}", &*MQTT_CONFIG.topic_prefix, model, serial);
    let alarm_status_clone = alarm_status_lock.clone();
    drop(alarm_status_lock);
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(event) => {
                    handle_event(event).await;
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                }
            }
        }
    });
    let mutex_client = MQTT_CLIENT.lock().await;
    let client = mutex_client.as_ref().unwrap();
    match publish_discovery(&client, &alarm_status_clone, &topic_prefix).await {
        Ok(_) => {
            info!("Discovery published");
        }
        Err(e) => {
            error!("Failed to publish discovery: {}", e);
        }
    }
    drop(mutex_client);
    let mutex_client = MQTT_CLIENT.lock().await;
    let client = mutex_client.as_ref().unwrap();
    match client
        .subscribe(format!("{}/command", topic_prefix), QOS)
        .await
    {
        Ok(_) => info!("Subscribed to command topic"),
        Err(e) => {
            error!("Failed to subscribe to command topic: {}", e);
        }
    };
    drop(mutex_client);

    tokio::select! {
        _ = async {
            loop {
                update_alarm_system().await;
                if *MQTT_PUBLISH.lock().await {
                    publish_alarm_status().await;
                    *MQTT_PUBLISH.lock().await = false;
                }
                time::sleep(Duration::from_secs(*REFRESH_INTERVAL)).await;
            }
        } => {}
    }
}

async fn setup() {
    let hostname = var("BASE_URL").unwrap_or_else(|_| {
        error!("No base URL found, use default");
        "visonic.tycomonitor.com".to_string()
    });
    let user_email = var("EMAIL").unwrap_or_else(|_| {
        error!("No email found, exiting");
        panic!("No email found");
    });
    let user_password = var("PASSWORD").unwrap_or_else(|_| {
        error!("No password found, exiting");
        panic!("No password found");
    });
    let user_code = var("USERCODE").unwrap_or_else(|_| {
        error!("No user code found, exiting");
        panic!("No user code found");
    });
    let panel_id = var("PANEL_ID").unwrap_or_else(|_| {
        error!("No panel ID found, exiting");
        panic!("No panel ID found");
    });
    let mut alarm_system = System::new(
        &hostname,
        &user_email,
        &user_password,
        &user_code,
        &panel_id,
    );
    if !alarm_system.connect().await {
        panic!("Failed to connect to the alarm system");
    }
    alarm_system.update_status().await;
    alarm_system.update_devices().await;
    *ALARM_SYSTEM_STATUS.lock().await = alarm_system.get_status();
    *ALARM_SYSTEM.lock().await = Some(alarm_system);
    *MQTT_PUBLISH.lock().await = true;
}

async fn handle_event(event: rumqttc::Event) {
    let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
    let model = alarm_status_lock.model().to_lowercase();
    let serial = alarm_status_lock.serial_number().to_lowercase();
    let topic_prefix = format!("{}/{}_{}", &*MQTT_CONFIG.topic_prefix, model, serial);
    drop(alarm_status_lock);
    let payload = parse_payload(event).await.unwrap();
    if payload.is_null() {
        return;
    }
    match payload["topic"].as_str() {
        Some(topic) => {
            if topic == format!("{}/command", topic_prefix) {
                match payload["payload"].as_str() {
                    Some(payload) => match payload {
                        "ARM_AWAY" => {
                            let mut alarm_system_lock = ALARM_SYSTEM.lock().await;
                            let alarm_system = alarm_system_lock.as_mut().unwrap();
                            let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
                            let alarm_status = alarm_status_lock.clone();
                            if alarm_status.state() == "AWAY" {
                                info!("Already armed away");
                                return;
                            }
                            drop(alarm_status_lock);
                            match alarm_system.arm_away().await {
                                Ok(_) => {
                                    info!("Armed away");
                                }
                                Err(e) => {
                                    error!("Failed to arm away: {}", e);
                                }
                            }
                            update_alarm_system().await;
                            *MQTT_PUBLISH.lock().await = true;
                        }
                        "ARM_HOME" => {
                            let mut alarm_system_lock = ALARM_SYSTEM.lock().await;
                            let alarm_system = alarm_system_lock.as_mut().unwrap();
                            let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
                            let alarm_status = alarm_status_lock.clone();
                            if alarm_status.state() == "HOME" {
                                info!("Already armed home");
                                return;
                            }
                            drop(alarm_status_lock);
                            match alarm_system.arm_home().await {
                                Ok(_) => {
                                    info!("Armed home");
                                }
                                Err(e) => {
                                    error!("Failed to arm home: {}", e);
                                }
                            }
                            update_alarm_system().await;
                            *MQTT_PUBLISH.lock().await = true;
                        }
                        "DISARM" => {
                            let mut alarm_system_lock = ALARM_SYSTEM.lock().await;
                            let alarm_system = alarm_system_lock.as_mut().unwrap();
                            let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
                            let alarm_status = alarm_status_lock.clone();
                            if alarm_status.state() == "DISARM" {
                                info!("Already disarmed");
                                return;
                            }
                            drop(alarm_status_lock);
                            match alarm_system.disarm().await {
                                Ok(_) => {
                                    info!("Disarmed");
                                }
                                Err(e) => {
                                    error!("Failed to disarm: {}", e);
                                }
                            }
                            update_alarm_system().await;
                            *MQTT_PUBLISH.lock().await = true;
                        }
                        _ => {}
                    },
                    None => {
                        error!("No payload found");
                    }
                }
            }
        }
        None => {
            error!("No topic found");
        }
    }
}

async fn update_alarm_system() {
    info!("Updating alarm system");
    let mut alarm_system = ALARM_SYSTEM.lock().await;
    let alarm_system = alarm_system.as_mut().unwrap();
    alarm_system.update_status().await;
    alarm_system.update_devices().await;
    *MQTT_PUBLISH.lock().await = true;
}

async fn publish_alarm_status() {
    let alarm_status_lock = ALARM_SYSTEM_STATUS.lock().await;
    let model = alarm_status_lock.model().to_lowercase();
    let serial = alarm_status_lock.serial_number().to_lowercase();
    let topic_prefix = format!("{}/{}_{}", &*MQTT_CONFIG.topic_prefix, model, serial);
    let mutex_client = MQTT_CLIENT.lock().await;
    let client = mutex_client.as_ref();
    if client.is_some() {
        let client = client.unwrap();
        match publish_state(&client, &alarm_status_lock, &topic_prefix).await {
            Ok(_) => {
                info!("State published");
            }
            Err(e) => {
                error!("Failed to publish state: {}", e);
            }
        };
    } else {
        let (mut client, mut eventloop) = mqtt_setup().await.unwrap();
        let alarm_status_clone = alarm_status_lock.clone();
        tokio::spawn(async move {
            match publish_state(&mut client, &alarm_status_clone, &topic_prefix).await {
                Ok(_) => {
                    info!("State published");
                }
                Err(e) => {
                    error!("Failed to publish state: {}", e);
                }
            };
            client.disconnect().await.unwrap();
        });
        tokio::spawn(async move {
            let mut packet_count: usize = 0;
            while packet_count < 4 {
                match eventloop.poll().await {
                    Ok(notification) => match notification {
                        rumqttc::Event::Outgoing(rumqttc::Outgoing::Publish(_)) => {
                            packet_count += 1;
                        }
                        _ => {
                            continue;
                        }
                    },
                    Err(e) => {
                        error!("Error: {:?}", e);
                    }
                }
            }
        });
    }
    drop(alarm_status_lock);
    drop(mutex_client);
}
