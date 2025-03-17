use chrono::{DateTime, Utc};
use log::{debug, error, info};
use rand::prelude::*;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, QoS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env::var, fs, sync::LazyLock, time::Duration};

use crate::visonic;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MQTTConfiguration {
    broker: String,
    port: u16,
    user: String,
    password: String,
    discovery_topic: String,
    pub topic_prefix: String,
}

const MQTT_CONFIG_FILE: &str = "data/mqtt.json";
pub static MQTT_CONFIG: LazyLock<MQTTConfiguration> = LazyLock::new(|| {
    let mqtt_broker = var("MQTT_BROKER");
    let mqtt_port = var("MQTT_PORT");
    let mqtt_user = var("MQTT_USER");
    let mqtt_password = var("MQTT_PASSWORD");
    let mqtt_discovery_topic = var("MQTT_DISCOVERY_TOPIC");
    let mqtt_topic_prefix = var("MQTT_TOPIC_PREFIX");
    if mqtt_broker.is_ok() && mqtt_port.is_ok() {
        let mqtt_config = MQTTConfiguration {
            broker: mqtt_broker.unwrap(),
            port: mqtt_port.unwrap().parse().unwrap_or(1883),
            user: mqtt_user.unwrap_or("".to_string()),
            password: mqtt_password.unwrap_or("".to_string()),
            discovery_topic: mqtt_discovery_topic.unwrap_or("homeassistant".to_string()),
            topic_prefix: mqtt_topic_prefix.unwrap_or("visonic2mqtt".to_string()),
        };
        fs::write(
            MQTT_CONFIG_FILE,
            serde_json::to_string(&mqtt_config).unwrap(),
        )
        .unwrap();
        mqtt_config
    } else {
        match fs::read_to_string(MQTT_CONFIG_FILE) {
            Ok(content) => match serde_json::from_str::<MQTTConfiguration>(&content) {
                Ok(config) => config,
                Err(e) => {
                    error!("Failed to parse MQTT configuration file: {}", e);
                    MQTTConfiguration {
                        broker: "localhost".to_string(),
                        port: 1883,
                        user: "".to_string(),
                        password: "".to_string(),
                        discovery_topic: "homeassistant".to_string(),
                        topic_prefix: "visonic2mqtt".to_string(),
                    }
                }
            },
            Err(e) => {
                error!("Failed to read MQTT configuration file: {}", e);
                MQTTConfiguration {
                    broker: "localhost".to_string(),
                    port: 1883,
                    user: "".to_string(),
                    password: "".to_string(),
                    discovery_topic: "homeassistant".to_string(),
                    topic_prefix: "visonic2mqtt".to_string(),
                }
            }
        }
    }
});

pub const QOS: QoS = QoS::AtMostOnce;

pub async fn setup() -> Result<(AsyncClient, EventLoop), Box<dyn std::error::Error>> {
    info!("Setting up MQTT client");
    // randomize the client id 6 alphanumeric characters
    let id: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    let id = format!("visonic2mqtt-{}", id);
    let mut mqttoptions = MqttOptions::new(id, &*MQTT_CONFIG.broker, MQTT_CONFIG.port);
    mqttoptions.set_keep_alive(Duration::from_secs(10));
    mqttoptions.set_credentials(&*MQTT_CONFIG.user, &*MQTT_CONFIG.password);

    let (client, eventloop) = AsyncClient::new(mqttoptions, 10);
    info!("Connected to MQTT broker");
    Ok((client, eventloop))
}

pub async fn parse_payload(event: Event) -> Result<Value, Box<dyn std::error::Error>> {
    match event {
        Event::Incoming(incoming) => match incoming {
            rumqttc::Packet::Publish(publish) => {
                debug!("Received message on topic: {}", publish.topic);
                debug!("Payload: {:?}", publish.payload);
                let payload = String::from_utf8_lossy(&publish.payload);
                let value: Value = json!({
                    "topic": publish.topic,
                    "payload": payload,
                });
                Ok(value)
            }
            _ => Ok(Value::Null),
        },
        _ => Ok(Value::Null),
    }
}

pub async fn publish_discovery(
    client: &AsyncClient,
    alarm_status: &visonic::SystemStatus,
    topic_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Publishing discovery");
    let name = format!(
        "{}_{}",
        alarm_status.model().to_lowercase(),
        alarm_status.serial_number().to_lowercase()
    );
    let device = json!({
        "ids": name,
        "name": name,
        "sw": "VISONIC2MQTT 1.0",
        "mdl": alarm_status.model(),
        "mf": "Visonic",
        "sn": alarm_status.serial_number(),
    });
    let availability_topic = format!("{}/availability", topic_prefix);
    let availability = json!(
        [{"topic": availability_topic.clone(), "value_template": "{{ value }}"}]
    );
    let attributes_topic = format!("{}/attributes", topic_prefix);
    let mut payload_map: HashMap<String, String> = HashMap::new();
    payload_map.insert(
        availability_topic.clone(),
        if alarm_status.connected() {
            "online"
        } else {
            "offline"
        }
        .to_string(),
    );
    payload_map.insert(
        format!(
            "{}/alarm_control_panel/{}_{}/config",
            &*MQTT_CONFIG.discovery_topic, &name, "panel"
        ),
        json!({
            "availability": availability,
            "name": format!("{} Panel", alarm_status.model()),
            "unique_id": format!("{}_panel", name),
            "code_arm_required": false,
            "code_disarm_required": false,
            "code_trigger_required": false,
            "command_topic": format!("{}/command", topic_prefix),
            "icon": "mdi:shield",
            "state_topic": format!("{}/state", topic_prefix),
            "value_template": "{{ value_json.state if (value_json is defined and value_json.state is defined) else None }}",
            "supported_features": ["arm_home", "arm_away"],
            "json_attributes_topic": attributes_topic.clone(),
            "json_attributes_template": "{{ value }}",
            "device": device,
        })
        .to_string()
    );
    alarm_status.devices().iter().for_each(|d| {
        payload_map.insert(
            format!(
                "{}/binary_sensor/{}_{}/config",
                &*MQTT_CONFIG.discovery_topic, &name, d.id().to_lowercase()
            ),
            json!({
                "availability": availability,
                "name": format!("{} {}", alarm_status.model(), if d.name() != "" { d.name() } else { d.id() }),
                "unique_id": format!("{}_{}", name, d.id()),
                "device_class": "door",
                "state_topic": format!("{}/state", topic_prefix),
                "value_template": format!("{{{{ value_json['{}'] if (value_json is defined and value_json['{}'] is defined) else 'OFF' }}}}", d.id().to_lowercase(), d.id().to_lowercase()),
                "json_attributes_topic": attributes_topic.clone(),
                "json_attributes_template": "{{ value }}",
                "device": device,
            })
            .to_string()
        );
    });
    for (topic, payload) in payload_map.iter() {
        debug!("Publishing: {} => {}", topic, payload);
        match client.publish(topic, QOS, true, payload.to_string()).await {
            Ok(_) => {
                debug!("Published: {} => {}", topic, payload);
            }
            Err(e) => {
                error!("Failed to publish discovery: {}", e);
            }
        }
    }
    info!("Discovery published");
    Ok(())
}

pub async fn publish_state(
    client: &AsyncClient,
    alarm_status: &visonic::SystemStatus,
    topic_prefix: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Publishing state");
    let availability_topic = format!("{}/availability", topic_prefix);
    let attributes_topic = format!("{}/attributes", topic_prefix);
    let state_topic = format!("{}/state", topic_prefix);
    let mut payload_map: HashMap<String, String> = HashMap::new();
    payload_map.insert(
        availability_topic.clone(),
        if alarm_status.connected() {
            "online"
        } else {
            "offline"
        }
        .to_string(),
    );
    let mut changed_by = "".to_string();
    let mut changed_time = DateTime::<Utc>::MIN_UTC;
    match alarm_status.last_event() {
        Some(event) => {
            changed_by = event.user.to_string();
            changed_time = event.timestamp;
        }
        None => {}
    }
    payload_map.insert(
        attributes_topic.clone(),
        json!({
            "serial_number": alarm_status.serial_number(),
            "model": alarm_status.model(),
            "ready": alarm_status.ready(),
            "connected": alarm_status.connected(),
            "last_updated": alarm_status.last_update(),
            "changed_by": changed_by,
            "changed_time": changed_time,
            "alarms": alarm_status.alarm(),
        })
        .to_string(),
    );
    let panel_state = match alarm_status.state().as_str() {
        "AWAY" => "armed_away",
        "CUSTOM_BYPASS" => "armed_custom_bypass",
        "HOME" => "armed_home",
        "NIGHT" => "armed_night",
        "VACATION" => "armed_vacation",
        "ARMING" => "arming",
        "DISARM" => "disarmed",
        "DISARMING" => "disarming",
        "PENDING" => "pending",
        "ALARM" => "triggered",
        _ => "unknown",
    };
    let mut state: HashMap<String, String> = HashMap::new();
    state.insert("state".to_string(), panel_state.to_string());
    alarm_status.devices().iter().for_each(|d| {
        let id = d.id().to_lowercase();
        let device_state = d.state();
        state.insert(id.clone(), device_state.to_string());
    });
    payload_map.insert(state_topic.clone(), json!(state).to_string());
    for (topic, payload) in payload_map.iter() {
        debug!("Publishing: {} => {}", topic, payload);
        match client.publish(topic, QOS, true, payload.to_string()).await {
            Ok(_) => {
                debug!("Published: {} => {}", topic, payload);
            }
            Err(e) => {
                error!("Failed to publish state: {}", e);
            }
        }
    }
    info!("State published");
    Ok(())
}
