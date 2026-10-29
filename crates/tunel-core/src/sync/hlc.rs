//! Reloj lógico híbrido: ordena los cambios de varios equipos aunque sus relojes difieran.
//!
//! Cada marca combina la hora en milisegundos, un contador para los cambios dentro del
//! mismo milisegundo y el equipo que la generó, que desempata.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub millis: u64,
    pub counter: u32,
    pub device: Uuid,
}

impl Hlc {
    /// Marca inicial de un equipo, anterior a cualquier cambio.
    pub fn zero(device: Uuid) -> Self {
        Self {
            millis: 0,
            counter: 0,
            device,
        }
    }

    /// Siguiente marca local a partir de esta, la última emitida.
    pub fn tick(self, wall_millis: u64) -> Self {
        if wall_millis > self.millis {
            Self {
                millis: wall_millis,
                counter: 0,
                ..self
            }
        } else {
            Self {
                counter: self.counter.saturating_add(1),
                ..self
            }
        }
    }

    /// Avanza esta marca para que la siguiente local quede por delante de `remote`.
    pub fn observe(self, remote: Hlc, wall_millis: u64) -> Self {
        let millis = self.millis.max(remote.millis).max(wall_millis);
        let counter = match (millis == self.millis, millis == remote.millis) {
            (true, true) => self.counter.max(remote.counter),
            (true, false) => self.counter,
            (false, true) => remote.counter,
            (false, false) => 0,
        };
        Self {
            millis,
            counter,
            device: self.device,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn tick_follows_the_wall_clock_and_counts_within_a_millisecond() {
        let start = Hlc::zero(device(1));
        let a = start.tick(1000);
        let b = a.tick(1000);
        let c = b.tick(999);
        let d = c.tick(2000);
        assert_eq!((a.millis, a.counter), (1000, 0));
        assert_eq!((b.millis, b.counter), (1000, 1));
        assert_eq!((c.millis, c.counter), (1000, 2));
        assert_eq!((d.millis, d.counter), (2000, 0));
        assert!(a < b && b < c && c < d);
    }

    #[test]
    fn after_observing_a_remote_mark_local_marks_come_later() {
        let local = Hlc::zero(device(1)).tick(1000);
        let remote = Hlc {
            millis: 5000,
            counter: 7,
            device: device(2),
        };
        let next = local.observe(remote, 1200).tick(1200);
        assert!(next > remote);
        assert_eq!(next.device, device(1));
    }

    #[test]
    fn device_breaks_ties() {
        let a = Hlc {
            millis: 10,
            counter: 0,
            device: device(1),
        };
        let b = Hlc {
            device: device(2),
            ..a
        };
        assert!(a < b);
    }
}
