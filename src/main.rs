mod logging;

fn main() {
    let _ = logging::init_logger();
    visonic2mqtt_lib::run();
}
