use std::{
    io::{Read, Write},
    net::TcpStream,
    time::Duration,
};

use zenoh_result::{zerror, ZResult};

use crate::api::robot_status_reporting::{
    RobotConnectionStatus, RobotStatusEvent, RobotStatusReporter,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpReporterConfig {
    pub(crate) endpoint: String,
    pub(crate) project_id: String,
    pub(crate) auth_token: String,
    // TODO(robot-status-reporting): add TLS and certificate validation support.
}

#[derive(Debug)]
pub(crate) struct HttpReporter {
    config: HttpReporterConfig,
}

impl HttpReporter {
    pub(crate) fn new(config: HttpReporterConfig) -> Self {
        Self { config }
    }

    fn build_path(&self, robot_id: &str, status: RobotConnectionStatus) -> String {
        let status = match status {
            RobotConnectionStatus::Online => "ONLINE",
            RobotConnectionStatus::Offline => "OFFLINE",
        };
        format!(
            "/v1/{}/robots/{}/status?status={status}",
            self.config.project_id, robot_id
        )
    }

    fn host_port(endpoint: &str) -> ZResult<&str> {
        endpoint
            .strip_prefix("http://")
            .ok_or_else(|| zerror!("unsupported endpoint scheme, expected http://").into())
    }
}

impl RobotStatusReporter for HttpReporter {
    fn report(&self, event: RobotStatusEvent) -> ZResult<()> {
        let host_port = Self::host_port(&self.config.endpoint)?;
        let mut stream = TcpStream::connect(host_port)
            .map_err(|e| zerror!("failed to connect reporter endpoint: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| zerror!("failed to set read timeout: {e}"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|e| zerror!("failed to set write timeout: {e}"))?;

        let path = self.build_path(&event.robot_id, event.status);
        let request = format!(
            "PATCH {path} HTTP/1.1\r\nHost: {host_port}\r\nX-Auth-Token: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            self.config.auth_token
        );

        stream
            .write_all(request.as_bytes())
            .map_err(|e| zerror!("failed to write request: {e}"))?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|e| zerror!("failed to read response: {e}"))?;

        let status_code = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| zerror!("invalid HTTP response status line"))?;

        if status_code != "200" {
            return Err(
                zerror!("robot status report failed with HTTP status {status_code}").into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    use crate::api::robot_status_reporting::{
        HttpReporter, HttpReporterConfig, RobotConnectionStatus, RobotStatusEvent,
        RobotStatusReporter, RobotStatusTrigger,
    };

    fn spawn_server(status_code: u16) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            tx.send(String::from_utf8_lossy(&buf[..n]).to_string())
                .unwrap();
            let status_line = if status_code == 200 {
                "HTTP/1.1 200 OK"
            } else {
                "HTTP/1.1 500 Internal Server Error"
            };
            let response =
                format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            stream.write_all(response.as_bytes()).unwrap();
        });

        (format!("http://{addr}"), rx)
    }

    fn sample_event(status: RobotConnectionStatus) -> RobotStatusEvent {
        RobotStatusEvent {
            session_id: "session-1".to_string(),
            robot_id: "robot-a".to_string(),
            status,
            trigger: RobotStatusTrigger::SessionOpen,
        }
    }

    #[test]
    fn http_reporter_sends_expected_method_path_and_header() {
        let (endpoint, rx) = spawn_server(200);
        let reporter = HttpReporter::new(HttpReporterConfig {
            endpoint,
            project_id: "project-1".to_string(),
            auth_token: "token-123".to_string(),
        });

        reporter
            .report(sample_event(RobotConnectionStatus::Online))
            .unwrap();

        let request = rx.recv().unwrap();
        assert!(
            request.starts_with("PATCH /v1/project-1/robots/robot-a/status?status=ONLINE HTTP/1.1")
        );
        assert!(request.contains("\r\nX-Auth-Token: token-123\r\n"));
    }

    #[test]
    fn http_reporter_accepts_only_200() {
        let (endpoint, _rx) = spawn_server(500);
        let reporter = HttpReporter::new(HttpReporterConfig {
            endpoint,
            project_id: "project-1".to_string(),
            auth_token: "token-123".to_string(),
        });

        let result = reporter.report(sample_event(RobotConnectionStatus::Offline));
        assert!(result.is_err());
    }

    #[test]
    fn http_reporter_rejects_non_http_endpoint() {
        let reporter = HttpReporter::new(HttpReporterConfig {
            endpoint: "https://example.com".to_string(),
            project_id: "project-1".to_string(),
            auth_token: "token-123".to_string(),
        });

        let result = reporter.report(sample_event(RobotConnectionStatus::Offline));
        assert!(result.is_err());
    }
}
