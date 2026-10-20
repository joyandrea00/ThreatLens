package threatlens_api.api;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import threatlens_api.detection.LoginEvent;
import threatlens_api.detection.ThreatDetectionService;

import java.util.List;

@CrossOrigin(origins = {
    "http://localhost:5173",
    "https://threatlens-aga8.onrender.com"
})
@RestController
@RequestMapping("/api/detection")
public class DetectionController {

    private final ThreatDetectionService detectionService;

    public DetectionController(ThreatDetectionService detectionService) {
        this.detectionService = detectionService;
    }

    @PostMapping("/analyze")
    public List<ThreatDetectionService.DetectionAlert> analyze(
            @RequestBody List<LoginEvent> events) {

        return detectionService.analyze(events);
    }
}