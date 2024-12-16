use std::sync::Once;
use log::{Level, LevelFilter};

static INIT: Once = Once::new();

pub struct Logger {
    level: Level,
}

impl Logger {
    pub fn new(level: Level) {
        INIT.call_once(|| {
            log::set_boxed_logger(Box::new(Logger { level }))
                .map(|()| log::set_max_level(LevelFilter::Trace))
                .expect("Failed to initialize logger");
        });
    }
}
