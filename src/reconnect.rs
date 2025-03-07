use crate::{asynch::client::ReconnectionConfig, errors::Error};
use rand::Rng;
use std::
    time::Instant
;

pub(crate) struct ReconnectionManager {
    pub config: ReconnectionConfig,
    pub current_attempt: usize,
    pub last_attempt_time: Instant,
    pub current_delay: f64,
}

impl ReconnectionManager {
    pub fn new(config: ReconnectionConfig) -> Self {
        Self {
            config: config.clone(),
            current_attempt: 0,
            last_attempt_time: Instant::now(),
            current_delay: config.initial_retry_delay,
        }
    }

    pub fn should_attempt_reconnect(&mut self) -> bool {
        if !self.config.auto_reconnect {
            return false;
        }

        // Check if max attempts exceeded
        if let Some(max) = self.config.max_attempts {
            if self.current_attempt >= max {
                return false;
            }
        }

        // Check if enough time has passed since last attempt
        let elapsed = self.last_attempt_time.elapsed().as_secs_f64();
        if elapsed < self.current_delay {
            return false;
        }

        true
    }

    pub fn next_attempt(&mut self) -> f64 {
        self.current_attempt += 1;
        self.last_attempt_time = Instant::now();

        // Apply jitter to prevent thundering herd
        let jitter_factor = 1.0 + (rand::random::<f64>() * 2.0 - 1.0) * self.config.jitter;
        let delay = self.current_delay * jitter_factor;

        // Calculate next delay with exponential backoff
        self.current_delay =
            (self.current_delay * self.config.backoff_factor).min(self.config.max_retry_delay);

        delay
    }

    pub fn reset(&mut self) {
        self.current_attempt = 0;
        self.current_delay = self.config.initial_retry_delay;
        self.last_attempt_time = Instant::now();
    }

    pub fn get_endpoints(&self) -> Vec<(String, u16)> {
        self.config.endpoints.clone()
    }

    pub fn should_reinitialize(&self) -> bool {
        self.config.reinitialize
    }
}
