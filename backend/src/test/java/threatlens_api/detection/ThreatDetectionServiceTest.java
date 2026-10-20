package threatlens_api.detection;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ThreatDetectionServiceTest {

    private final ThreatDetectionService service =
            new ThreatDetectionService();

    @Test
    void normalLoginActivityShouldNotCreateAlerts() {
        List<LoginEvent> events = List.of(
                new LoginEvent("joy", "192.168.1.10", true,
                        Instant.parse("2026-10-19T10:00:00Z")),
                new LoginEvent("alex", "192.168.1.11", true,
                        Instant.parse("2026-10-19T10:01:00Z"))
        );

        assertTrue(service.analyze(events).isEmpty());
    }

    @Test
    void fiveFailedLoginsShouldCreateAnAlert() {
        List<LoginEvent> events = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
            events.add(new LoginEvent(
                    "joy", "203.0.113.10", false,
                    Instant.parse("2026-10-19T10:00:00Z")
                            .plusSeconds(i * 10L)
            ));
        }

        var alerts = service.analyze(events);

        assertFalse(alerts.isEmpty());
        assertTrue(alerts.stream().anyMatch(
                alert -> alert.sourceIp().equals("203.0.113.10")
                        && alert.riskScore() >= 40
        ));
    }

    @Test
    void threeDifferentUsernamesFromOneIpShouldCreateHighAlert() {
        List<LoginEvent> events = List.of(
                new LoginEvent("joy", "203.0.113.20", true,
                        Instant.parse("2026-10-19T10:00:00Z")),
                new LoginEvent("alex", "203.0.113.20", false,
                        Instant.parse("2026-10-19T10:01:00Z")),
                new LoginEvent("sam", "203.0.113.20", false,
                        Instant.parse("2026-10-19T10:02:00Z"))
        );

        var alerts = service.analyze(events);

        assertTrue(alerts.stream().anyMatch(
                alert -> alert.sourceIp().equals("203.0.113.20")
                        && alert.severity().equals("HIGH")
        ));
    }
}