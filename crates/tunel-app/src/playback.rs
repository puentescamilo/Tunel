//! Reproducir una grabación de sesión en una pestaña de solo lectura, con pausa y
//! velocidad. Las pausas largas se acortan, como hace asciinema.

use std::time::{Duration, Instant};
use tunel_core::sync::recording::RecordingEvent;
use tunel_sync::audit::Trust;
use tunel_sync::recording::Recording;

/// Ninguna pausa dura más que esto al reproducir.
const MAX_IDLE_MS: u64 = 2000;
pub const SPEEDS: [u32; 4] = [1, 2, 4, 8];

/// Lo que se sabe de la grabación, para la barra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaybackInfo {
    pub complete: bool,
    pub trust: Trust,
    pub problem: Option<String>,
}

pub struct Playback {
    events: Vec<RecordingEvent>,
    next: usize,
    position_ms: u64,
    last_tick: Option<Instant>,
    pub speed: u32,
    pub paused: bool,
    pub duration_ms: u64,
    pub info: PlaybackInfo,
}

/// Los eventos con las pausas largas acortadas a `MAX_IDLE_MS`.
fn without_long_pauses(events: &[RecordingEvent]) -> Vec<RecordingEvent> {
    let mut shift = 0;
    let mut previous = 0;
    events
        .iter()
        .map(|event| {
            let at = event.at_ms();
            shift += at.saturating_sub(previous).saturating_sub(MAX_IDLE_MS);
            previous = at.max(previous);
            let at_ms = at.saturating_sub(shift);
            match event.clone() {
                RecordingEvent::Output { data, .. } => RecordingEvent::Output { at_ms, data },
                RecordingEvent::Resize { cols, rows, .. } => {
                    RecordingEvent::Resize { at_ms, cols, rows }
                }
            }
        })
        .collect()
}

impl Playback {
    pub fn new(recording: &Recording) -> Self {
        let events = without_long_pauses(&recording.events);
        Self {
            duration_ms: events.last().map_or(0, RecordingEvent::at_ms),
            events,
            next: 0,
            position_ms: 0,
            last_tick: None,
            speed: 1,
            paused: false,
            info: PlaybackInfo {
                complete: recording.complete,
                trust: recording.trust,
                problem: recording.problem.clone(),
            },
        }
    }

    pub fn position_ms(&self) -> u64 {
        self.position_ms
    }

    pub fn finished(&self) -> bool {
        self.next >= self.events.len()
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.last_tick = None;
    }

    /// Avanza el reloj hasta `now` y devuelve los eventos que tocan.
    pub fn advance(&mut self, now: Instant) -> Vec<RecordingEvent> {
        let elapsed = self
            .last_tick
            .map_or(0, |t| now.duration_since(t).as_millis() as u64);
        self.last_tick = (!self.paused).then_some(now);
        if !self.paused {
            self.position_ms = self
                .position_ms
                .saturating_add(elapsed.saturating_mul(self.speed as u64));
        }
        self.take_until(self.position_ms)
    }

    /// Salta al final: devuelve todo lo que falta.
    pub fn skip_to_end(&mut self) -> Vec<RecordingEvent> {
        self.position_ms = self.duration_ms;
        self.take_until(u64::MAX)
    }

    fn take_until(&mut self, position: u64) -> Vec<RecordingEvent> {
        let start = self.next;
        while self
            .events
            .get(self.next)
            .is_some_and(|e| e.at_ms() <= position)
        {
            self.next += 1;
        }
        self.events[start..self.next].to_vec()
    }

    /// Cuánto falta para el próximo evento, para despertar a la interfaz.
    pub fn wait(&self) -> Option<Duration> {
        if self.paused {
            return None;
        }
        let next = self.events.get(self.next)?.at_ms();
        let ms = next.saturating_sub(self.position_ms) / self.speed as u64;
        Some(Duration::from_millis(ms.clamp(1, 250)))
    }
}

/// `mm:ss` de unos milisegundos.
pub fn clock(ms: u64) -> String {
    let seconds = ms / 1000;
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(at_ms: u64) -> RecordingEvent {
        RecordingEvent::Output {
            at_ms,
            data: vec![b'x'],
        }
    }

    fn playback(events: Vec<RecordingEvent>) -> Playback {
        Playback::new(&Recording {
            header: None,
            events,
            complete: true,
            trust: Trust::Verified,
            problem: None,
        })
    }

    #[test]
    fn long_pauses_are_shortened() {
        let events = without_long_pauses(&[output(0), output(500), output(60_500), output(61_000)]);
        let times: Vec<u64> = events.iter().map(RecordingEvent::at_ms).collect();
        assert_eq!(times, [0, 500, 2500, 3000]);
    }

    #[test]
    fn events_come_out_as_time_passes_at_the_chosen_speed() {
        let mut p = playback(vec![output(0), output(1000), output(2000)]);
        let start = Instant::now();
        assert_eq!(p.advance(start).len(), 1);
        assert_eq!(p.advance(start + Duration::from_millis(999)).len(), 0);
        assert_eq!(p.advance(start + Duration::from_millis(1000)).len(), 1);
        p.speed = 4;
        assert_eq!(p.advance(start + Duration::from_millis(1250)).len(), 1);
        assert!(p.finished());
        assert_eq!(p.wait(), None);
    }

    #[test]
    fn a_paused_playback_stays_put_and_can_jump_to_the_end() {
        let mut p = playback(vec![output(0), output(1000), output(2000)]);
        let start = Instant::now();
        p.advance(start);
        p.toggle_pause();
        assert!(p.advance(start + Duration::from_secs(10)).is_empty());
        assert_eq!(p.position_ms(), 0);
        assert_eq!(p.skip_to_end().len(), 2);
        assert_eq!(p.position_ms(), 2000);
        assert_eq!(clock(61_000), "01:01");
    }
}
