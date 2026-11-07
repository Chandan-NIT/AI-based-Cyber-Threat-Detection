import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";

function Home() {
  const [isScanning, setIsScanning] = useState(false);
  const [recentScans, setRecentScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [recentThreats, setRecentThreats] = useState([]);
  const [alert, setAlert] = useState(null);
  const lastThreatId = useRef(null);

  // Settings
  const [showSettings, setShowSettings] = useState(false);
  const [apiIp, setApiIp] = useState(
    localStorage.getItem("apiIp") || "127.0.0.1"
  );
  const [tempIp, setTempIp] = useState(
    localStorage.getItem("apiIp") || "127.0.0.1"
  );

  const API_BASE = `http://${apiIp}:8000`;

  const saveSettings = () => {
    const cleanedIp = tempIp.trim();

    if (!cleanedIp) {
      return;
    }

    localStorage.setItem("apiIp", cleanedIp);
    setApiIp(cleanedIp);
    setShowSettings(false);
  };

  // Request browser notification permission
  useEffect(() => {
    if ("Notification" in window) {
      if (Notification.permission === "default") {
        Notification.requestPermission();
      }
    }
  }, []);

  // Fetch dashboard data
  useEffect(() => {
    const fetchScans = () => {
      fetch(`${API_BASE}/recent-scans`)
        .then((response) => response.json())
        .then((data) => {
          setRecentScans(data.scans);
        })
        .catch((error) => {
          console.error("Failed to fetch recent scans:", error);
        });
    };

    const fetchThreats = () => {
      fetch(`${API_BASE}/attacks`)
        .then((response) => response.json())
        .then((data) => {
          setRecentThreats(data);

          if (data.length === 0) {
            return;
          }

          const latestThreat = data[0];

          // First load
          if (lastThreatId.current === null) {
            lastThreatId.current = latestThreat.id;
            return;
          }

          // New threat
          if (latestThreat.id !== lastThreatId.current) {
            lastThreatId.current = latestThreat.id;

            const threatType = latestThreat.prediction;

            // Show toast
            setAlert({
              id: latestThreat.id,
              type: threatType,
              source: latestThreat.source_ip,
              destination: latestThreat.destination_ip,
              score: latestThreat.prediction_score,
            });

            // Show browser notification
            if (
              "Notification" in window &&
              Notification.permission === "granted"
            ) {
              new Notification(
                threatType === "DDoS"
                  ? "🚨 DDoS Attack Detected"
                  : "⚠️ Port Scan Detected",
                {
                  body:
                    `${latestThreat.source_ip} → ` +
                    `${latestThreat.destination_ip}\n` +
                    `Confidence: ${(
                      latestThreat.prediction_score * 100
                    ).toFixed(1)}%`,
                  tag: `threat-${latestThreat.id}`,
                }
              );
            }

            // Automatically hide toast after 5 seconds
            setTimeout(() => {
              setAlert(null);
            }, 5000);
          }
        })
        .catch((error) => {
          console.error("Failed to fetch Threats:", error);
        });
    };

    const fetchStats = () => {
      fetch(`${API_BASE}/statistics`)
        .then((response) => response.json())
        .then((data) => {
          setStats(data);
        })
        .catch((error) => {
          console.error("Failed to fetch statistics:", error);
        });
    };

    fetchScans();
    fetchStats();
    fetchThreats();

    const interval = setInterval(() => {
      fetchScans();
      fetchStats();
      fetchThreats();
    }, 2000);

    return () => clearInterval(interval);
  }, [API_BASE]);

  // Check scan status
  useEffect(() => {
    const checkStatus = () => {
      fetch(`${API_BASE}/scan-status`)
        .then((response) => response.json())
        .then((data) => {
          setIsScanning(data.running);
        })
        .catch((error) => {
          console.error("Failed to fetch scan status:", error);
        });
    };

    checkStatus();

    const interval = setInterval(checkStatus, 2000);

    return () => clearInterval(interval);
  }, [API_BASE]);

  const scan = recentScans.length > 0 ? recentScans[0] : null;

  const getProtocolName = (protocol) => {
    if (protocol === 6) return "TCP";
    if (protocol === 17) return "UDP";

    return protocol;
  };

  const handleScanToggle = async () => {
    const endpoint = isScanning
      ? `${API_BASE}/stop-scan`
      : `${API_BASE}/start-scan`;

    try {
      const response = await fetch(endpoint, {
        method: "POST",
      });

      const data = await response.json();

      if (
        data.status === "started" ||
        data.status === "already_running"
      ) {
        setIsScanning(true);
      }

      if (
        data.status === "stopped" ||
        data.status === "not_running"
      ) {
        setIsScanning(false);
      }
    } catch (error) {
      console.error("Failed to control scan:", error);
    }
  };

  return (
    <div className="min-h-screen w-full overflow-x-hidden bg-slate-100">

      {/* Threat Alert Toast */}
      {alert && (
        <div className="fixed left-4 right-4 top-4 z-[100] sm:left-auto sm:right-6 sm:top-6 sm:w-96">
          <div
            className={`rounded-xl border p-4 shadow-2xl sm:p-5 ${
              alert.type === "DDoS"
                ? "border-red-200 bg-red-50"
                : "border-orange-200 bg-orange-50"
            }`}
          >
            <div className="flex items-start gap-3 sm:gap-4">

              {/* Icon */}
              <div
                className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-xl sm:h-11 sm:w-11 ${
                  alert.type === "DDoS"
                    ? "bg-red-100 text-red-600"
                    : "bg-orange-100 text-orange-600"
                }`}
              >
                {alert.type === "DDoS" ? "!" : "⚠"}
              </div>

              {/* Content */}
              <div className="min-w-0 flex-1">

                <div className="flex items-start justify-between gap-2 sm:gap-3">

                  <div className="min-w-0">
                    <p
                      className={`text-sm font-bold ${
                        alert.type === "DDoS"
                          ? "text-red-700"
                          : "text-orange-700"
                      }`}
                    >
                      {alert.type === "DDoS"
                        ? "DDoS Attack Detected"
                        : "Port Scan Detected"}
                    </p>

                    <p className="mt-1 text-xs text-slate-500">
                      Behavioral analysis detected malicious activity.
                    </p>
                  </div>

                  <button
                    onClick={() => setAlert(null)}
                    className="shrink-0 text-lg leading-none text-slate-400 hover:text-slate-700"
                  >
                    ×
                  </button>

                </div>

                <div className="mt-4 space-y-1.5 text-xs">

                  <div className="flex flex-wrap justify-between gap-1 sm:gap-3">
                    <span className="text-slate-500">
                      Source
                    </span>

                    <span className="break-all text-right font-mono font-semibold text-slate-700">
                      {alert.source || "N/A"}
                    </span>
                  </div>

                  <div className="flex flex-wrap justify-between gap-1 sm:gap-3">
                    <span className="text-slate-500">
                      Destination
                    </span>

                    <span className="break-all text-right font-mono font-semibold text-slate-700">
                      {alert.destination || "N/A"}
                    </span>
                  </div>

                  <div className="flex justify-between gap-3">
                    <span className="text-slate-500">
                      Confidence
                    </span>

                    <span className="font-semibold text-slate-700">
                      {((alert.score || 0) * 100).toFixed(1)}%
                    </span>
                  </div>

                </div>

              </div>

            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b bg-white px-4 py-4 sm:px-6 sm:py-5 lg:px-8">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

          {/* Brand */}
          <div className="min-w-0">
            <h1 className="text-xl font-bold text-slate-900 sm:text-2xl">
              KAVACH AI
            </h1>

            <p className="text-xs text-slate-500 sm:text-sm">
              AI-Based Cyber Threat Detection
            </p>
          </div>

          {/* Header Controls */}
          <div className="flex w-full flex-col gap-3 lg:w-auto lg:flex-row lg:items-center lg:gap-6">

            {/* IP */}
            <div className="min-w-0 border-b pb-3 text-xs font-medium text-slate-600 sm:text-sm lg:border-b-0 lg:border-r lg:px-4 lg:py-2 lg:pr-6">
              <span className="text-slate-400 sm:hidden">
                Backend:{" "}
              </span>
              <span className="break-all">
                Current IP: {apiIp}:8000
              </span>
            </div>

            {/* Monitoring Status */}
            <div className="flex items-center gap-2 border-b pb-3 lg:border-b-0 lg:border-r lg:pr-6">

              <span
                className={`h-2.5 w-2.5 shrink-0 rounded-full sm:h-3 sm:w-3 ${
                  isScanning
                    ? "animate-pulse bg-green-500"
                    : "bg-slate-400"
                }`}
              />

              <span className="text-xs font-medium text-slate-700 sm:text-sm">
                {isScanning
                  ? "LIVE MONITORING"
                  : "MONITORING OFF"}
              </span>

            </div>

            {/* Navigation */}
            <nav className="flex w-full items-center gap-2 sm:w-auto">

              <Link
                to="/"
                className="flex-1 rounded-lg bg-slate-900 px-3 py-2.5 text-center text-xs font-medium text-white sm:flex-none sm:px-4 sm:py-2 sm:text-sm"
              >
                Live Monitoring
              </Link>

              <Link
                to="/stats"
                className="flex-1 rounded-lg px-3 py-2.5 text-center text-xs font-medium text-slate-600 transition hover:bg-slate-100 sm:flex-none sm:px-4 sm:py-2 sm:text-sm"
              >
                Statistics
              </Link>

              {/* Settings Button */}
              <button
                onClick={() => {
                  setTempIp(apiIp);
                  setShowSettings(true);
                }}
                className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-xl text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                title="Settings"
              >
                ⚙
              </button>

            </nav>

          </div>
        </div>
      </header>

      {/* Settings Overlay */}
      {showSettings && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/20 p-4 pt-16 sm:pt-24"
          onClick={() => setShowSettings(false)}
        >
          <div
            className="w-full max-w-sm rounded-xl bg-white p-5 shadow-2xl sm:p-6"
            onClick={(event) => event.stopPropagation()}
          >

            <div className="flex items-center justify-between">

              <div>
                <h2 className="text-lg font-semibold text-slate-900">
                  Settings
                </h2>

                <p className="mt-1 text-sm text-slate-500">
                  Configure backend connection
                </p>
              </div>

              <button
                onClick={() => setShowSettings(false)}
                className="text-xl text-slate-400 transition hover:text-slate-700"
              >
                ×
              </button>

            </div>

            <div className="mt-6">

              <label className="text-sm font-medium text-slate-700">
                Backend IP Address
              </label>

              <input
                type="text"
                value={tempIp}
                onChange={(event) => setTempIp(event.target.value)}
                placeholder="127.0.0.1"
                className="mt-2 w-full rounded-lg border border-slate-300 px-4 py-2.5 font-mono text-sm outline-none transition focus:border-slate-500 focus:ring-2 focus:ring-slate-200"
              />

              <p className="mt-2 text-xs text-slate-400">
                Example: 192.168.1.105
              </p>

            </div>

            <button
              onClick={saveSettings}
              className="mt-6 w-full rounded-lg bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800"
            >
              Save Settings
            </button>

            <p className="mt-4 text-center text-xs text-slate-400">
              Tap outside to go back
            </p>

          </div>
        </div>
      )}

      {/* Main */}
      <main className="mx-auto w-full max-w-7xl space-y-5 p-4 sm:space-y-6 sm:p-6 lg:p-6">

        {/* Dashboard Summary */}
        {stats && (
          <section className="grid w-full grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">

            <StatCard
              title="Total Flows"
              value={stats.total_flows}
              icon="↗"
              color="text-slate-700"
              background="bg-slate-50"
            />

            <StatCard
              title="Benign Flows"
              value={stats.benign}
              icon="✓"
              color="text-green-600"
              background="bg-green-50"
            />

            <StatCard
              title="DDoS Attacks"
              value={stats.ddos}
              icon="!"
              color="text-red-600"
              background="bg-red-50"
            />

            <StatCard
              title="PortScan Attacks"
              value={stats.portscan}
              icon="⚠"
              color="text-orange-600"
              background="bg-orange-50"
            />

          </section>
        )}

        {/* Live Detection */}
        <section className="w-full rounded-xl bg-slate-900 p-5 text-white shadow-sm sm:p-6">

          <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">

            <div className="min-w-0">
              <div className="flex items-center gap-3">

                <span
                  className={`h-3 w-3 shrink-0 rounded-full ${
                    isScanning
                      ? "animate-pulse bg-green-400"
                      : "bg-slate-500"
                  }`}
                />

                <h2 className="text-lg font-semibold sm:text-xl">
                  Live Detection
                </h2>

              </div>

              <p className="mt-2 text-sm text-slate-400">
                Continuously monitor incoming network traffic
              </p>
            </div>

            <button
              onClick={handleScanToggle}
              className={`w-full rounded-lg px-5 py-3 text-sm font-semibold transition sm:w-auto sm:py-2.5 ${
                isScanning
                  ? "bg-red-500 hover:bg-red-600"
                  : "bg-green-500 hover:bg-green-600"
              }`}
            >
              {isScanning ? "Stop Scan" : "Start Scan"}
            </button>

          </div>

          {isScanning && (
            <div className="mt-5 rounded-lg border border-green-500/20 bg-green-500/10 px-4 py-3 text-sm text-green-400">

              <div className="flex items-start gap-2">

                <span className="mt-1 h-2 w-2 shrink-0 animate-pulse rounded-full bg-green-400" />

                <span>
                  Scanning incoming network traffic...
                </span>

              </div>

            </div>
          )}

        </section>

        {/* Live Detection Table */}
        <section className="w-full rounded-xl bg-white p-4 shadow-sm sm:p-6">

          <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">

            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                Live Detection Table
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Recently processed network flows
              </p>
            </div>

            <span className="w-fit rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
              {recentScans.length} flows
            </span>

          </div>

          {/* Horizontal scrolling on small screens */}
          <div className="max-h-96 overflow-auto rounded-lg">

            <table className="min-w-[850px] w-full text-left text-sm">

              <thead className="sticky top-0 z-10 bg-slate-50">

                <tr className="border-b text-xs uppercase tracking-wide text-slate-500">

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Time
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Source IP
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Destination IP
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Protocol
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Packets
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Prediction
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Confidence
                  </th>

                </tr>

              </thead>

              <tbody>

                {recentScans.map((scan) => (

                  <tr
                    key={scan.id}
                    className="border-b last:border-0 transition hover:bg-slate-50"
                  >

                    <td className="whitespace-nowrap px-4 py-4 text-slate-600">
                      {new Date(
                        scan.timestamp
                      ).toLocaleTimeString()}
                    </td>

                    <td className="whitespace-nowrap px-4 py-4 font-mono text-slate-700">
                      {scan.source_ip || "N/A"}
                    </td>

                    <td className="whitespace-nowrap px-4 py-4 font-mono text-slate-700">
                      {scan.destination_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4">

                      <span className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">
                        {getProtocolName(scan.protocol)}
                      </span>

                    </td>

                    <td className="px-4 py-4 text-slate-700">
                      {scan.packet_count}
                    </td>

                    <td className="px-4 py-4">
                      <PredictionBadge
                        prediction={scan.prediction}
                      />
                    </td>

                    <td className="px-4 py-4">

                      <div className="flex items-center gap-3">

                        <div className="h-2 w-20 shrink-0 overflow-hidden rounded-full bg-slate-200">

                          <div
                            className={`h-full rounded-full ${
                              scan.prediction === "BENIGN"
                                ? "bg-green-500"
                                : "bg-red-500"
                            }`}
                            style={{
                              width: `${
                                scan.prediction_score * 100
                              }%`,
                            }}
                          />

                        </div>

                        <span className="whitespace-nowrap font-semibold text-slate-700">
                          {(
                            scan.prediction_score * 100
                          ).toFixed(1)}
                          %
                        </span>

                      </div>

                    </td>

                  </tr>

                ))}

                {recentScans.length === 0 && (

                  <tr>

                    <td
                      colSpan="7"
                      className="px-4 py-12 text-center"
                    >

                      <p className="font-medium text-slate-700">
                        No network flows detected yet
                      </p>

                      <p className="mt-1 text-sm text-slate-400">
                        Start monitoring to begin collecting traffic.
                      </p>

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        </section>

        {/* Recent Threats */}
        <section className="w-full rounded-xl bg-white p-4 shadow-sm sm:p-6">

          <div className="mb-5">

            <h2 className="text-lg font-semibold text-slate-900">
              Recent Threats
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Recently detected malicious network activity
            </p>

          </div>

          <div className="max-h-96 overflow-auto rounded-lg">

            <table className="min-w-[750px] w-full text-left text-sm">

              <thead className="sticky top-0 z-10">

                <tr className="border-b bg-slate-50 text-xs uppercase tracking-wide text-slate-500">

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Time
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Source IP
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Destination IP
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Protocol
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Prediction
                  </th>

                  <th className="whitespace-nowrap px-4 py-3 font-semibold">
                    Score
                  </th>

                </tr>

              </thead>

              <tbody>

                {recentThreats.slice(0, 5).map((threat) => (

                  <tr
                    key={threat.id}
                    className="border-b last:border-0 transition hover:bg-slate-50"
                  >

                    <td className="whitespace-nowrap px-4 py-4 text-slate-600">
                      {new Date(
                        threat.timestamp
                      ).toLocaleTimeString()}
                    </td>

                    <td className="whitespace-nowrap px-4 py-4 font-mono text-slate-700">
                      {threat.source_ip || "N/A"}
                    </td>

                    <td className="whitespace-nowrap px-4 py-4 font-mono text-slate-700">
                      {threat.destination_ip || "N/A"}
                    </td>

                    <td className="px-4 py-4">

                      <span className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">
                        {getProtocolName(threat.protocol)}
                      </span>

                    </td>

                    <td className="px-4 py-4">
                      <PredictionBadge
                        prediction={threat.prediction}
                      />
                    </td>

                    <td className="whitespace-nowrap px-4 py-4 font-semibold text-slate-700">
                      {(
                        threat.prediction_score * 100
                      ).toFixed(1)}
                      %
                    </td>

                  </tr>

                ))}

                {recentThreats.length === 0 && (

                  <tr>

                    <td
                      colSpan="6"
                      className="px-4 py-12 text-center"
                    >

                      <div className="flex flex-col items-center">

                        <div className="flex h-12 w-12 items-center justify-center rounded-full bg-green-50 text-xl text-green-600">
                          ✓
                        </div>

                        <p className="mt-3 font-medium text-slate-700">
                          No Threats detected
                        </p>

                        <p className="mt-1 text-sm text-slate-400">
                          Network traffic is currently classified as safe.
                        </p>

                      </div>

                    </td>

                  </tr>

                )}

              </tbody>

            </table>

          </div>

        </section>

        {/* Alert History */}
        <section className="w-full rounded-xl bg-white p-4 shadow-sm sm:p-6">

          <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">

            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                Alert History
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Latest 50 detected security threats
              </p>
            </div>

            <div className="w-fit rounded-full bg-red-50 px-3 py-1.5 text-xs font-semibold text-red-600">
              {stats ? stats.ddos + stats.portscan : 0} Total Alerts
            </div>

          </div>

          {recentThreats.length === 0 ? (

            <div className="rounded-lg border border-dashed border-slate-200 py-12 text-center">

              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-50 text-xl text-green-600">
                ✓
              </div>

              <p className="mt-3 font-medium text-slate-700">
                No alerts in history
              </p>

              <p className="mt-1 px-4 text-sm text-slate-400">
                Detected DDoS and Port Scan attacks will appear here.
              </p>

            </div>

          ) : (

            <div className="max-h-96 overflow-auto rounded-lg">

              <table className="min-w-[950px] w-full text-left text-sm">

                <thead className="sticky top-0 z-10">

                  <tr className="border-b bg-slate-50 text-xs uppercase tracking-wide text-slate-500">

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Time
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Threat
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Source
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Destination
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Protocol
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Packets
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Bytes
                    </th>

                    <th className="whitespace-nowrap px-4 py-3 font-semibold">
                      Confidence
                    </th>

                  </tr>

                </thead>

                <tbody>

                  {recentThreats.map((threat) => (

                    <tr
                      key={threat.id}
                      className="border-b border-slate-100 last:border-0 transition hover:bg-slate-50"
                    >

                      {/* Time */}
                      <td className="whitespace-nowrap px-4 py-4 text-slate-600">
                        {threat.timestamp
                          ? new Date(
                              threat.timestamp
                            ).toLocaleString()
                          : "N/A"}
                      </td>

                      {/* Threat */}
                      <td className="px-4 py-4">

                        <PredictionBadge
                          prediction={threat.prediction}
                        />

                      </td>

                      {/* Source */}
                      <td className="whitespace-nowrap px-4 py-4">

                        <span className="font-mono text-xs font-medium text-slate-700">
                          {threat.source_ip || "N/A"}
                        </span>

                      </td>

                      {/* Destination */}
                      <td className="whitespace-nowrap px-4 py-4">

                        <span className="font-mono text-xs font-medium text-slate-700">
                          {threat.destination_ip || "N/A"}
                        </span>

                      </td>

                      {/* Protocol */}
                      <td className="px-4 py-4">

                        <span className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700">
                          {getProtocolName(threat.protocol)}
                        </span>

                      </td>

                      {/* Packets */}
                      <td className="px-4 py-4 font-medium text-slate-700">
                        {threat.packet_count ?? 0}
                      </td>

                      {/* Bytes */}
                      <td className="whitespace-nowrap px-4 py-4 font-medium text-slate-700">
                        {threat.total_bytes
                          ? Number(
                              threat.total_bytes
                            ).toLocaleString()
                          : "0"}
                      </td>

                      {/* Confidence */}
                      <td className="whitespace-nowrap px-4 py-4">

                        <span className="font-semibold text-slate-700">
                          {threat.prediction_score != null
                            ? `${(
                                Number(
                                  threat.prediction_score
                                ) * 100
                              ).toFixed(1)}%`
                            : "N/A"}
                        </span>

                      </td>

                    </tr>

                  ))}

                </tbody>

              </table>

            </div>

          )}

        </section>

        {/* Recent Scan Details */}
        {scan && (
          <section className="w-full rounded-xl bg-white p-5 shadow-sm sm:p-6">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-900">
                Recent Scan Details
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Metadata from the latest network flow
              </p>

            </div>

            <div className="grid grid-cols-1 gap-x-6 gap-y-5 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">

              <Detail
                label="Timestamp"
                value={new Date(
                  scan.timestamp
                ).toLocaleString()}
              />

              <Detail
                label="Source IP"
                value={scan.source_ip || "N/A"}
              />

              <Detail
                label="Destination IP"
                value={scan.destination_ip || "N/A"}
              />

              <Detail
                label="Protocol"
                value={getProtocolName(scan.protocol)}
              />

              <Detail
                label="Source Port"
                value={scan.source_port}
              />

              <Detail
                label="Destination Port"
                value={scan.destination_port}
              />

              <Detail
                label="Packets"
                value={scan.packet_count}
              />

              <Detail
                label="Bytes"
                value={scan.total_bytes}
              />

              <Detail
                label="Duration"
                value={`${scan.duration} s`}
              />

            </div>

          </section>
        )}

        {!scan && (
          <section className="w-full rounded-xl bg-white p-8 text-center shadow-sm sm:p-10">

            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-slate-100 text-2xl text-slate-400">
              —
            </div>

            <p className="mt-4 font-medium text-slate-700">
              No scan data available yet
            </p>

            <p className="mt-1 px-4 text-sm text-slate-400">
              Start the live detector to generate network flow data.
            </p>

          </section>
        )}

        {/* Latest AI Prediction */}
        {scan && (
          <section className="w-full rounded-xl bg-white p-5 shadow-sm sm:p-6">

            <div className="mb-5">

              <h2 className="text-lg font-semibold text-slate-900">
                Latest AI Prediction
              </h2>

              <p className="mt-1 text-sm text-slate-500">
                Random Forest classification result
              </p>

            </div>

            <div className="grid gap-5 lg:grid-cols-2 lg:gap-6">

              {/* Scan Metadata */}
              <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 sm:p-5">

                <div className="mb-5 flex flex-wrap items-center justify-between gap-2">

                  <h3 className="font-semibold text-slate-800">
                    Scan Metadata
                  </h3>

                  <span className="rounded-md bg-white px-2 py-1 text-xs font-medium text-slate-500 shadow-sm">
                    Latest Flow
                  </span>

                </div>

                <div className="space-y-3 text-sm">

                  <Info
                    label="Source IP"
                    value={scan.source_ip || "N/A"}
                  />

                  <Info
                    label="Destination IP"
                    value={scan.destination_ip || "N/A"}
                  />

                  <Info
                    label="Source Port"
                    value={scan.source_port}
                  />

                  <Info
                    label="Destination Port"
                    value={scan.destination_port}
                  />

                  <Info
                    label="Protocol"
                    value={getProtocolName(scan.protocol)}
                  />

                  <Info
                    label="Packets"
                    value={scan.packet_count}
                  />

                  <Info
                    label="Bytes"
                    value={scan.total_bytes}
                  />

                  <Info
                    label="Duration"
                    value={`${scan.duration} s`}
                  />

                </div>

              </div>

              {/* Prediction */}
              <div className="flex flex-col items-center justify-center rounded-xl border border-slate-200 bg-slate-50 p-6 sm:p-8">

                <p className="text-sm font-medium uppercase tracking-wide text-slate-500">
                  AI Prediction
                </p>

                <p
                  className={`mt-3 max-w-full break-words text-center text-4xl font-bold sm:text-5xl ${
                    scan.prediction === "BENIGN"
                      ? "text-green-600"
                      : "text-red-600"
                  }`}
                >
                  {scan.prediction}
                </p>

                <div className="mt-6 w-full max-w-sm">

                  <div className="mb-2 flex items-center justify-between gap-3 text-sm">

                    <span className="text-slate-500">
                      Prediction Confidence
                    </span>

                    <span className="whitespace-nowrap font-semibold text-slate-800">
                      {(
                        scan.prediction_score * 100
                      ).toFixed(2)}
                      %
                    </span>

                  </div>

                  <div className="h-3 overflow-hidden rounded-full bg-slate-200">

                    <div
                      className={`h-full rounded-full transition-all ${
                        scan.prediction === "BENIGN"
                          ? "bg-green-500"
                          : "bg-red-500"
                      }`}
                      style={{
                        width: `${
                          scan.prediction_score * 100
                        }%`,
                      }}
                    />

                  </div>

                </div>

                <p className="mt-5 max-w-md text-center text-xs text-slate-400">
                  Classification generated by the trained Random Forest model.
                </p>

              </div>

            </div>

          </section>
        )}

      </main>
    </div>
  );
}

function PredictionBadge({ prediction }) {
  const isBenign = prediction === "BENIGN";
  const isDDoS = prediction === "DDoS";

  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-3 py-1 text-xs font-semibold ${
        isBenign
          ? "bg-green-100 text-green-700"
          : isDDoS
          ? "bg-red-100 text-red-700"
          : "bg-orange-100 text-orange-700"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 shrink-0 rounded-full ${
          isBenign
            ? "bg-green-500"
            : isDDoS
            ? "bg-red-500"
            : "bg-orange-500"
        }`}
      />

      {prediction}
    </span>
  );
}

function Detail({ label, value }) {
  return (
    <div className="min-w-0">
      <p className="text-xs font-medium uppercase tracking-wide text-slate-400">
        {label}
      </p>

      <p className="mt-1 break-all font-semibold text-slate-800">
        {value}
      </p>
    </div>
  );
}

function Info({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-200 pb-2">

      <span className="shrink-0 text-slate-500">
        {label}
      </span>

      <span className="min-w-0 break-all text-right font-mono font-medium text-slate-800">
        {value}
      </span>

    </div>
  );
}

function StatCard({
  title,
  value,
  icon,
  color,
  background,
}) {
  return (
    <div className="rounded-xl bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md sm:p-6">

      <div className="flex items-start justify-between gap-4">

        <div className="min-w-0">

          <p className="text-sm font-medium text-slate-500">
            {title}
          </p>

          <p
            className={`mt-2 text-2xl font-bold sm:text-3xl ${color}`}
          >
            {value}
          </p>

        </div>

        <div
          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-lg font-bold ${background} ${color}`}
        >
          {icon}
        </div>

      </div>

    </div>
  );
}

export default Home;