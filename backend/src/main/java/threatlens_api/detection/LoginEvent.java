
package threatlens_api.detection;

import java.time.Instant;

public record LoginEvent(
        String username,
        String sourceIp,
        boolean successful,
        Instant timestamp
) {
}
