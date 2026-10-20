package threatlens_api.detection;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ThreatDetectionService {

    public record DetectionAlert(
            String username,
            String sourceIp,
            int riskScore,
            String severity,
            List<String> reasons
    ) {}

    public List<DetectionAlert> analyze(List<LoginEvent> events) {
        List<DetectionAlert> alerts = new ArrayList<>();
        Map<String, List<LoginEvent>> eventsByIp = new HashMap<>();

        for (LoginEvent event : events) {
            if (event == null || event.username() == null
                    || event.sourceIp() == null
                    || event.timestamp() == null) {
                continue;
            }

            eventsByIp.computeIfAbsent(
                    event.sourceIp(), key -> new ArrayList<>()
            ).add(event);
        }

        for (Map.Entry<String, List<LoginEvent>> entry
                : eventsByIp.entrySet()) {

            String ip = entry.getKey();
            List<LoginEvent> ipEvents = entry.getValue();

            List<LoginEvent> failures = ipEvents.stream()
                    .filter(event -> !event.successful())
                    .toList();

            if (failures.size() >= 5) {
                int score = Math.min(100, 40 + failures.size() * 5);

                alerts.add(new DetectionAlert(
                        failures.get(0).username(),
                        ip,
                        score,
                        score >= 70 ? "HIGH" : "MEDIUM",
                        List.of(failures.size()
                                + " failed login attempts from this IP")
                ));
            }

            long distinctUsers = ipEvents.stream()
                    .map(LoginEvent::username)
                    .distinct()
                    .count();

            if (distinctUsers >= 3) {
                alerts.add(new DetectionAlert(
                        "Multiple accounts",
                        ip,
                        75,
                        "HIGH",
                        List.of(distinctUsers
                                + " different usernames targeted from one IP")
                ));
            }
        }

        return alerts;
    }
}