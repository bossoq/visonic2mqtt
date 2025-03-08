use chrono::prelude::*;
use log::{debug, error, info};
use reqwest::{header::HeaderMap, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Warning {
    #[serde(rename = "type")]
    _type: String,
    severity: String,
    in_memory: bool,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Device {
    id: i32,
    name: String,
    #[serde(rename = "zone_type")]
    zone: Option<String>,
    device_type: String,
    device_number: i32,
    subtype: String,
    preenroll: bool,
    warnings: Option<Vec<Warning>>,
    partitions: Vec<i32>,
}
impl Device {
    #[allow(dead_code)]
    pub fn id(&self) -> String {
        self.id.to_string()
    }
    #[allow(dead_code)]
    pub fn name(&self) -> String {
        self.name.clone()
    }
    #[allow(dead_code)]
    pub fn zone(&self) -> String {
        self.zone.clone().unwrap_or("".to_string())
    }
    #[allow(dead_code)]
    pub fn device_type(&self) -> String {
        self.device_type.clone()
    }
    #[allow(dead_code)]
    pub fn subtype(&self) -> String {
        self.subtype.clone()
    }
    #[allow(dead_code)]
    pub fn preenroll(&self) -> bool {
        self.preenroll
    }
    #[allow(dead_code)]
    pub fn warnings(&self) -> Option<Vec<Warning>> {
        self.warnings.clone()
    }
    #[allow(dead_code)]
    pub fn partitions(&self) -> Vec<i32> {
        self.partitions.clone()
    }
    #[allow(dead_code)]
    pub fn state(&self) -> String {
        if self.subtype.contains("CONTACT")
            || self.subtype == "HW_ZONE_CONNECTED_DIRECTLY_TO_THE_PANEL"
            || self.subtype.contains("KEYFOB")
        {
            match &self.warnings {
                Some(warning) => {
                    if warning.iter().any(|w| w._type == "OPENED") {
                        return "ON".to_string();
                    } else {
                        return "OFF".to_string();
                    }
                }
                None => return "OFF".to_string(),
            }
        } else {
            return "UNKNOWN".to_string();
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Event {
    #[serde(rename = "event")]
    event_id: i32,
    #[serde(rename = "label")]
    action: String,
    #[serde(rename = "appointment")]
    pub user: String,
    #[serde(rename = "datetime", with = "my_date_format")]
    pub timestamp: DateTime<Utc>,
}
mod my_date_format {
    use chrono::{DateTime, NaiveDateTime, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";

    // The signature of a serialize_with function must follow the pattern:
    //
    //    fn serialize<S>(&T, S) -> Result<S::Ok, S::Error>
    //    where
    //        S: Serializer
    //
    // although it may also be generic over the input types T.
    pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<'de, D>(D) -> Result<T, D::Error>
    //    where
    //        D: Deserializer<'de>
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let dt = NaiveDateTime::parse_from_str(&s, FORMAT).map_err(serde::de::Error::custom)?;
        Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Partition {
    id: i32,
    state: String,
    status: String,
    ready: bool,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct PanelStatus {
    connected: bool,
    partitions: Vec<Partition>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ProcessStatus {
    token: String,
    status: String,
    message: String,
    error: Option<String>,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemStatus {
    serial: Option<String>,
    model: Option<String>,
    ready: bool,
    state: String,
    connected: bool,
    alarm: bool,
    devices: Vec<Device>,
    last_update: DateTime<Utc>,
    last_event: Option<Event>,
}
impl SystemStatus {
    #[allow(dead_code)]
    pub fn default() -> Self {
        SystemStatus {
            serial: None,
            model: None,
            ready: false,
            state: "Unknown".to_string(),
            connected: false,
            alarm: false,
            devices: Vec::new(),
            last_update: Utc::now(),
            last_event: None,
        }
    }
    #[allow(dead_code)]
    pub fn serial_number(&self) -> String {
        self.serial.as_ref().unwrap().to_string()
    }
    #[allow(dead_code)]
    pub fn model(&self) -> String {
        self.model.as_ref().unwrap().to_string()
    }
    #[allow(dead_code)]
    pub fn ready(&self) -> bool {
        self.ready
    }
    #[allow(dead_code)]
    pub fn state(&self) -> String {
        self.state.clone()
    }
    #[allow(dead_code)]
    pub fn connected(&self) -> bool {
        self.connected
    }
    #[allow(dead_code)]
    pub fn alarm(&self) -> bool {
        self.alarm
    }
    #[allow(dead_code)]
    pub fn devices(&self) -> Vec<Device> {
        self.devices.clone()
    }
    #[allow(dead_code)]
    pub fn get_device_by_id(&self, id: &str) -> Option<Device> {
        self.devices.iter().find(|d| d.id() == id).cloned()
    }
    #[allow(dead_code)]
    pub fn last_update(&self) -> DateTime<Utc> {
        self.last_update
    }
    #[allow(dead_code)]
    pub fn last_event(&self) -> Option<Event> {
        self.last_event.clone()
    }
}
pub struct System {
    api: API,
    serial: Option<String>,
    model: Option<String>,
    ready: bool,
    state: String,
    connected: bool,
    alarm: bool,
    devices: Vec<Device>,
    last_update: DateTime<Utc>,
    last_event: Option<Event>,
}
impl System {
    pub fn new(
        hostname: &str,
        user_email: &str,
        user_password: &str,
        user_code: &str,
        panel_id: &str,
    ) -> Self {
        System {
            api: API::new(hostname, user_email, user_password, user_code, panel_id),
            serial: None,
            model: None,
            ready: false,
            state: "Unknown".to_string(),
            connected: false,
            alarm: false,
            devices: Vec::new(),
            last_update: Utc::now(),
            last_event: None,
        }
    }
    #[allow(dead_code)]
    pub fn get_status(&self) -> SystemStatus {
        SystemStatus {
            serial: self.serial.clone(),
            model: self.model.clone(),
            ready: self.ready,
            state: self.state.clone(),
            connected: self.connected,
            alarm: self.alarm,
            devices: self.devices.clone(),
            last_update: self.last_update,
            last_event: self.last_event.clone(),
        }
    }
    async fn is_token_valid(&self) -> bool {
        self.api.is_logged_in().await
    }
    #[allow(dead_code)]
    pub async fn disarm(&mut self) -> Result<bool, String> {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        match self.api.set_state(&ArmState::DISARM).await {
            Ok(res) => {
                let process_token = res["process_token"].as_str().unwrap();
                loop {
                    match self.api.process_status(process_token).await {
                        Ok(res) => match serde_json::from_value::<Vec<ProcessStatus>>(res) {
                            Ok(res) => {
                                if res.len() > 0 {
                                    match res[0].status.as_str() {
                                        "succeeded" => return Ok(true),
                                        "failed" => return Ok(false),
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => return Err(e.to_string()),
                        },
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
    #[allow(dead_code)]
    pub async fn arm_home(&mut self) -> Result<bool, String> {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        match self.api.set_state(&ArmState::HOME).await {
            Ok(res) => {
                let process_token = res["process_token"].as_str().unwrap();
                loop {
                    match self.api.process_status(process_token).await {
                        Ok(res) => match serde_json::from_value::<Vec<ProcessStatus>>(res) {
                            Ok(res) => {
                                if res.len() > 0 {
                                    match res[0].status.as_str() {
                                        "succeeded" => return Ok(true),
                                        "failed" => return Ok(false),
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => return Err(e.to_string()),
                        },
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
    #[allow(dead_code)]
    pub async fn arm_away(&mut self) -> Result<bool, String> {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        match self.api.set_state(&ArmState::AWAY).await {
            Ok(res) => {
                let process_token = res["process_token"].as_str().unwrap();
                loop {
                    match self.api.process_status(process_token).await {
                        Ok(res) => match serde_json::from_value::<Vec<ProcessStatus>>(res) {
                            Ok(res) => {
                                if res.len() > 0 {
                                    match res[0].status.as_str() {
                                        "succeeded" => return Ok(true),
                                        "failed" => return Ok(false),
                                        _ => {}
                                    }
                                }
                            }
                            Err(e) => return Err(e.to_string()),
                        },
                        Err(e) => return Err(e),
                    }
                }
            }
            Err(e) => Err(e),
        }
    }
    #[allow(dead_code)]
    pub async fn connect(&mut self) -> bool {
        let rest_versions = match self.api.get_version_info().await {
            Ok(res) => match res["rest_versions"].as_array() {
                Some(versions) => versions
                    .iter()
                    .map(|v| v.as_str().unwrap_or("").to_string())
                    .collect::<Vec<String>>(),
                None => {
                    error!("Failed to get rest versions");
                    return false;
                }
            },
            Err(e) => {
                error!("Failed to get version info: {}", e);
                return false;
            }
        };
        if rest_versions.contains(&"8.0".to_string()) {
            debug!("Setting rest version to 8.0");
            self.api.set_version_urls("8.0");
        } else if rest_versions.contains(&"9.0".to_string()) {
            debug!("Setting rest version to 9.0");
            self.api.set_version_urls("9.0");
        } else if rest_versions.contains(&"10.0".to_string()) {
            debug!("Setting rest version to 10.0");
            self.api.set_version_urls("10.0");
        } else if rest_versions.contains(&"12.0".to_string()) {
            debug!("Setting rest version to 12.0");
            self.api.set_version_urls("12.0");
        } else {
            error!("No supported rest version found");
            return false;
        }

        self.api.login().await;
        debug!("Logged in");
        self.api.panel_login().await;
        debug!("Panel logged in");

        match self.api.get_panel_info().await {
            Ok(res) => {
                self.serial = Some(res["serial"].as_str().unwrap_or("").to_string());
                self.model = Some(res["model"].as_str().unwrap_or("").to_string());
                debug!("Panel info retrieved");
            }
            Err(e) => {
                error!("Failed to get panel info: {}", e);
                return false;
            }
        }
        return true;
    }
    #[allow(dead_code)]
    pub async fn get_last_event(&mut self) {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        match self.api.get_events().await {
            Ok(res) => match serde_json::from_value::<Vec<Event>>(res) {
                Ok(events) => {
                    let last_event = events.first();
                    match last_event {
                        Some(last_event) => {
                            self.last_event = Some(last_event.clone());
                            debug!(
                                "Last event: {} at {} by {}",
                                last_event.action, last_event.timestamp, last_event.user
                            );
                        }
                        None => {
                            error!("No events found");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse events: {}", e);
                }
            },
            Err(e) => {
                error!("Failed to get events: {}", e);
            }
        }
    }
    #[allow(dead_code)]
    pub async fn update_status(&mut self) {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        match self.api.get_status().await {
            Ok(res) => match serde_json::from_value::<PanelStatus>(res) {
                Ok(res) => {
                    let first_partition = res.partitions.first();
                    match first_partition {
                        Some(first_partition) => {
                            self.ready = first_partition.ready;
                            self.connected = res.connected;
                            let old_state = self.state.clone();
                            let alarms = self.api.get_alarms().await;
                            if alarms.is_err()
                                || alarms
                                    .unwrap_or_default()
                                    .as_array()
                                    .unwrap_or(&vec![])
                                    .len()
                                    == 0
                            {
                                if first_partition.status == "EXIT"
                                    && (first_partition.state == "AWAY"
                                        || first_partition.state == "HOME")
                                {
                                    self.state = "ARMING".to_string();
                                } else {
                                    self.state = first_partition.state.clone();
                                    self.alarm = false;
                                }
                            } else {
                                self.alarm = true;
                                if first_partition.state == "HOME"
                                    || first_partition.state == "AWAY"
                                {
                                    self.state = "ALARM".to_string();
                                } else {
                                    self.state = first_partition.state.clone();
                                }
                            }
                            if old_state != self.state {
                                self.get_last_event().await;
                            }
                            self.last_update = Utc::now();
                            debug!("Status updated");
                        }
                        None => {
                            error!("No partitions found");
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to parse status: {}", e);
                }
            },
            Err(e) => {
                error!("Failed to get status: {}", e);
            }
        }
    }
    #[allow(dead_code)]
    pub async fn update_devices(&mut self) {
        if !self.is_token_valid().await {
            self.connect().await;
        }
        self.devices.clear();
        match self.api.get_devices().await {
            Ok(res) => match serde_json::from_value::<Vec<Device>>(res) {
                Ok(devices) => {
                    self.devices = devices;
                    self.last_update = Utc::now();
                    debug!("Devices updated");
                }
                Err(e) => {
                    error!("Failed to parse devices: {}", e);
                }
            },
            Err(e) => {
                error!("Failed to get devices: {}", e);
            }
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ArmState {
    HOME,
    AWAY,
    DISARM,
}
struct API {
    app_type: String,
    user_agent: String,
    rest_version: String,
    hostname: String,
    user_code: String,
    app_id: String,
    panel_id: String,
    partition: String,
    user_email: String,
    user_password: String,
    url_base: Option<String>,
    url_version: Option<String>,
    url_login: Option<String>,
    url_panel_login: Option<String>,
    url_status: Option<String>,
    url_alarms: Option<String>,
    url_alerts: Option<String>,
    url_troubles: Option<String>,
    url_panel_info: Option<String>,
    url_events: Option<String>,
    url_devices: Option<String>,
    url_set_state: Option<String>,
    url_process_status: Option<String>,
    user_token: Option<String>,
    session_token: Option<String>,
    client: Client,
}
impl API {
    fn new(
        hostname: &str,
        user_email: &str,
        user_password: &str,
        user_code: &str,
        panel_id: &str,
    ) -> Self {
        let mut api = API {
            app_type: "com.visonic.PowerMaxApp".to_string(),
            user_agent: "Visonic%20GO/2.8.62.91 CFNetwork/901.1 Darwin/17.6.0".to_string(),
            rest_version: "8.0".to_string(),
            hostname: hostname.to_string(),
            user_code: user_code.to_string(),
            app_id: Uuid::new_v4().to_string().to_ascii_uppercase(),
            panel_id: panel_id.to_string(),
            partition: "-1".to_string(),
            user_email: user_email.to_string(),
            user_password: user_password.to_string(),
            url_base: None,
            url_version: None,
            url_login: None,
            url_panel_login: None,
            url_status: None,
            url_alarms: None,
            url_alerts: None,
            url_troubles: None,
            url_panel_info: None,
            url_events: None,
            url_devices: None,
            url_set_state: None,
            url_process_status: None,
            user_token: None,
            session_token: None,
            client: Client::new(),
        };
        api.url_version = format!("https://{}/rest_api/version", api.hostname)
            .parse()
            .ok();
        return api;
    }
    async fn send_get_request(
        &self,
        url: &str,
        with_user_token: bool,
        with_session_token: bool,
    ) -> Result<Value, String> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", self.user_agent.parse().unwrap());
        if with_user_token {
            headers.insert(
                "User-Token",
                self.user_token.as_ref().unwrap().parse().unwrap(),
            );
        }
        if with_session_token {
            headers.insert(
                "Session-Token",
                self.session_token.as_ref().unwrap().parse().unwrap(),
            );
        }
        debug!("Sending GET request to {}", url);
        debug!("Headers: {:?}", headers);
        let res = self.client.get(url).headers(headers).send().await;
        match res {
            Ok(res) => {
                let status = res.status();
                debug!("Response status: {}", status);
                if status != 200 {
                    error!("Failed to get response: {}", status);
                    return Err("Failed to get response".to_string());
                }
                match res.json::<Value>().await {
                    Ok(res) => {
                        debug!("Response: {}", res);
                        return Ok(res);
                    }
                    Err(e) => {
                        error!("Failed to parse response: {}", e);
                        return Err("Failed to parse response".to_string());
                    }
                }
            }
            Err(e) => {
                error!("Failed to send request: {}", e);
                return Err("Failed to send request".to_string());
            }
        }
    }
    async fn send_post_request(
        &self,
        url: &str,
        data_json: &Value,
        with_user_token: bool,
        with_session_token: bool,
    ) -> Result<Value, String> {
        let mut headers = HeaderMap::new();
        headers.insert("User-Agent", self.user_agent.parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        if with_user_token {
            headers.insert(
                "User-Token",
                self.user_token.as_ref().unwrap().parse().unwrap(),
            );
        }
        if with_session_token {
            headers.insert(
                "Session-Token",
                self.session_token.as_ref().unwrap().parse().unwrap(),
            );
        }
        debug!("Sending POST request to {}", url);
        debug!("Headers: {:?}", headers);
        debug!("Payload: {:?}", data_json);
        let res = self
            .client
            .post(url)
            .headers(headers)
            .json(&data_json)
            .send()
            .await;
        match res {
            Ok(res) => {
                let status = res.status();
                debug!("Response status: {}", status);
                if status != 200 {
                    error!("Failed to get response: {}", status);
                    return Err("Failed to get response".to_string());
                }
                match res.json::<Value>().await {
                    Ok(res) => {
                        debug!("Response: {}", res);
                        return Ok(res);
                    }
                    Err(e) => {
                        error!("Failed to parse response: {}", e);
                        return Err("Failed to parse response".to_string());
                    }
                }
            }
            Err(e) => {
                error!("Failed to send request: {}", e);
                return Err("Failed to send request".to_string());
            }
        }
    }
    #[allow(dead_code)]
    pub fn user_token(&self) -> String {
        self.user_token.as_ref().unwrap().to_string()
    }
    fn set_user_token(&mut self, user_token: &str) {
        self.user_token = Some(user_token.to_string());
    }
    #[allow(dead_code)]
    pub fn session_token(&self) -> String {
        self.session_token.as_ref().unwrap().to_string()
    }
    fn set_session_token(&mut self, session_token: &str) {
        self.session_token = Some(session_token.to_string());
    }
    #[allow(dead_code)]
    pub fn hostname(&self) -> String {
        self.hostname.to_string()
    }
    #[allow(dead_code)]
    pub fn user_code(&self) -> String {
        self.user_code.to_string()
    }
    #[allow(dead_code)]
    pub fn app_id(&self) -> String {
        self.app_id.to_string()
    }
    #[allow(dead_code)]
    pub fn panel_id(&self) -> String {
        self.panel_id.to_string()
    }
    #[allow(dead_code)]
    pub fn partition(&self) -> String {
        self.partition.to_string()
    }
    #[allow(dead_code)]
    pub async fn get_version_info(&self) -> Result<Value, String> {
        let url = self.url_version.as_ref().unwrap();
        self.send_get_request(url, false, false).await
    }
    #[allow(dead_code)]
    pub fn set_version_urls(&mut self, version: &str) {
        self.rest_version = version.to_string();
        self.url_base = format!("https://{}/rest_api/{}", self.hostname, self.rest_version)
            .parse()
            .ok();
        self.url_login = format!("{}/auth", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_panel_login = format!("{}/panel/login", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_status = format!("{}/status", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_alarms = format!("{}/alarms", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_alerts = format!("{}/alerts", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_troubles = format!("{}/troubles", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_panel_info = format!("{}/panel_info", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_events = format!("{}/events", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_devices = format!("{}/devices", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_set_state = format!("{}/set_state", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
        self.url_process_status = format!("{}/process_status", self.url_base.as_ref().unwrap())
            .parse()
            .ok();
    }
    #[allow(dead_code)]
    pub async fn login(&mut self) {
        let data_json = json!({
            "email": self.user_email.clone(),
            "password": self.user_password.clone(),
            "app_id": self.app_id.clone(),
        });
        let url = self.url_login.as_ref().unwrap();
        let res = self.send_post_request(url, &data_json, false, false).await;
        match res {
            Ok(res) => {
                info!("Login successful");
                self.set_user_token(res["user_token"].as_str().unwrap());
            }
            Err(e) => {
                error!("Failed to login: {}", e);
            }
        }
    }
    #[allow(dead_code)]
    pub async fn panel_login(&mut self) {
        let data_json = json!({
            "user_code": self.user_code,
            "app_type": self.app_type,
            "app_id": self.app_id,
            "panel_serial": self.panel_id,
        });
        let url = self.url_panel_login.as_ref().unwrap();
        let res = self.send_post_request(url, &data_json, true, false).await;
        match res {
            Ok(res) => {
                info!("Panel login successful");
                self.set_session_token(res["session_token"].as_str().unwrap());
            }
            Err(e) => {
                error!("Failed to panel login: {}", e);
            }
        }
    }
    #[allow(dead_code)]
    pub async fn is_logged_in(&self) -> bool {
        self.get_status().await.is_ok()
    }
    #[allow(dead_code)]
    pub async fn get_status(&self) -> Result<Value, String> {
        let url = self.url_status.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_alarms(&self) -> Result<Value, String> {
        let url = self.url_alarms.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_alerts(&self) -> Result<Value, String> {
        let url = self.url_alerts.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_troubles(&self) -> Result<Value, String> {
        let url = self.url_troubles.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_panel_info(&self) -> Result<Value, String> {
        let url = self.url_panel_info.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_events(&self) -> Result<Value, String> {
        let url = self.url_events.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn get_devices(&self) -> Result<Value, String> {
        let url = self.url_devices.as_ref().unwrap();
        self.send_get_request(url, true, true).await
    }
    #[allow(dead_code)]
    pub async fn set_state(&self, state: &ArmState) -> Result<Value, String> {
        let state = match state {
            ArmState::HOME => "home".to_uppercase(),
            ArmState::AWAY => "away".to_uppercase(),
            ArmState::DISARM => "disarm".to_uppercase(),
        };
        let data_json = json!({
            "partition": self.partition,
            "state": state,
        });
        let url = self.url_set_state.as_ref().unwrap();
        self.send_post_request(url, &data_json, true, true).await
    }
    #[allow(dead_code)]
    pub async fn process_status(&self, process_token: &str) -> Result<Value, String> {
        let url = self.url_process_status.as_ref().unwrap();
        let url = format!("{}?process_token={}", url, process_token);
        self.send_get_request(&url, true, true).await
    }
}
