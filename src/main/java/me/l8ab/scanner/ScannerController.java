package me.l8ab.scanner;

import org.springframework.web.bind.annotation.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/api")
public class ScannerController {

    @PostMapping("/scan")
    public Map<String, Object> scanUrl(@RequestBody Map<String, String> payload) {
        String targetUrl = payload.get("url");
        Map<String, Object> result = new HashMap<>();
        List<String> vulnerabilities = new ArrayList<>();
        
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            result.put("status", "error");
            result.put("message", "Please enter a valid URL");
            return result;
        }

        if (!targetUrl.startsWith("http")) {
            targetUrl = "https://" + targetUrl;
        }

        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("User-Agent", "L8ab-Security-Scanner/1.0 (Educational)")
                    .build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, List<String>> headers = response.headers().map();
            
            checkHeader(headers, vulnerabilities, "X-Frame-Options", "Clickjacking Risk (X-Frame-Options Missing)");
            checkHeader(headers, vulnerabilities, "Content-Security-Policy", "XSS Risk (CSP Missing)");
            checkHeader(headers, vulnerabilities, "Strict-Transport-Security", "Insecure Connection (HSTS Missing)");
            checkHeader(headers, vulnerabilities, "X-Content-Type-Options", "MIME Sniffing Risk");
            checkHeader(headers, vulnerabilities, "Referrer-Policy", "Referrer Leakage Risk");

            result.put("status", "success");
            result.put("target", targetUrl);
            result.put("vulnerabilities", vulnerabilities);
            result.put("score", calculateScore(vulnerabilities.size()));

        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", "Could not connect to target: " + e.getMessage());
        }
        return result;
    }

    private void checkHeader(Map<String, List<String>> headers, List<String> vulns, String key, String msg) {
        if (headers.keySet().stream().noneMatch(k -> k.equalsIgnoreCase(key))) {
            vulns.add(msg);
        }
    }
    
    private String calculateScore(int issues) {
        if (issues == 0) return "A+ (SECURE)";
        if (issues < 3) return "B (WARNING)";
        return "F (CRITICAL)";
    }
}