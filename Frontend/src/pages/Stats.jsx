import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

function Stats() {

  const [stats, setStats] = useState(null);
  const [activity, setActivity] = useState([]);

  useEffect(() => {

    const fetchStats = () => {

      // Fetch overall statistics
      fetch("http://127.0.0.1:8000/statistics")
        .then((response) => response.json())
        .then((data) => {
          setStats(data);
        })
        .catch((error) => {
          console.error(
            "Failed to fetch statistics:",
            error
          );
        });

      // Fetch detection activity
      fetch("http://127.0.0.1:8000/detection-activity")
        .then((response) => response.json())
        .then((data) => {
          setActivity(data);
        })
        .catch((error) => {
          console.error(
            "Failed to fetch detection activity:",
            error
          );
        });

    };

    // Fetch immediately
    fetchStats();

    // Update every 2 seconds
    const interval = setInterval(fetchStats, 2000);

    // Cleanup
    return () => clearInterval(interval);

  }, []);


  // Loading state
  if (!stats) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-100">

        <p className="text-slate-500">
          Loading statistics...
        </p>

      </div>
    );
  }


  // Pie chart data
  // BENIGN is capped at 50 only for visualization
  const chartData = [
    {
      name: "BENIGN",
      value: Math.min(stats.benign, 50),
    },
    {
      name: "DDoS",
      value: stats.ddos,
    },
    {
      name: "PortScan",
      value: stats.portscan,
    },
  ];


  // Pie chart colors
  const colors = [
    "#22c55e", // BENIGN - Green
    "#ef4444", // DDoS - Red
    "#f97316", // PortScan - Orange
  ];


  // Activity graph data
  // Network flow count is capped at 50 only for visualization
  const activityData = activity.map((item) => ({
    ...item,
    total: Math.min(item.total, 50),
  }));


  return (
    <div className="min-h-screen bg-slate-100">

      {/* Header */}
      <header className="border-b bg-white px-8 py-5">

        <div className="flex items-center justify-between">

          <div>

            <h1 className="text-2xl font-bold text-slate-900">
              SIH26145
            </h1>

            <p className="text-sm text-slate-500">
              Cyber Threat Statistics
            </p>

          </div>


          <nav className="flex items-center gap-2">

            <Link
              to="/"
              className="rounded-lg px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100"
            >
              Live Monitoring
            </Link>

            <Link
              to="/stats"
              className="rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white"
            >
              Statistics
            </Link>

          </nav>

        </div>

      </header>


      <main className="mx-auto max-w-7xl space-y-6 p-6">

        {/* Summary Cards */}
        <section className="grid gap-5 md:grid-cols-2 lg:grid-cols-4">

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


        {/* Threat Distribution */}
        <section className="rounded-xl bg-white p-6 shadow-sm">

          <div className="mb-5">

            <h2 className="text-lg font-semibold text-slate-900">
              Traffic Classification
            </h2>

            <p className="text-sm text-slate-500">
              Distribution of detected network flows
            </p>

          </div>


          <div className="h-80">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <PieChart>

                <Pie
                  data={chartData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={110}
                  label
                >

                  {chartData.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={colors[index]}
                    />
                  ))}

                </Pie>

                <Tooltip />

                <Legend />

              </PieChart>

            </ResponsiveContainer>

          </div>

        </section>


        {/* Detection Activity */}
        <section className="rounded-xl bg-white p-6 shadow-sm">

          <div className="mb-5">

            <h2 className="text-lg font-semibold text-slate-900">
              Detection Activity
            </h2>

            <p className="text-sm text-slate-500">
              Network flows and detected threats over time
            </p>

          </div>


          <div className="h-80">

            <ResponsiveContainer
              width="100%"
              height="100%"
            >

              <LineChart data={activityData}>

                <CartesianGrid strokeDasharray="3 3" />

                <XAxis dataKey="time" />

                <YAxis allowDecimals={false} />

                <Tooltip />

                <Legend />

                {/* Network Flows */}
                <Line
                  type="monotone"
                  dataKey="total"
                  name="Network Flows"
                  stroke="#64748b"
                  strokeWidth={2}
                  dot={false}
                />

                {/* DDoS Attacks */}
                <Line
                  type="monotone"
                  dataKey="ddos"
                  name="DDoS Attacks"
                  stroke="#ef4444"
                  strokeWidth={2}
                  dot={false}
                />

                {/* PortScan Attacks */}
                <Line
                  type="monotone"
                  dataKey="portscan"
                  name="PortScan Attacks"
                  stroke="#f97316"
                  strokeWidth={2}
                  dot={false}
                />

              </LineChart>

            </ResponsiveContainer>

          </div>

        </section>

      </main>

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
    <div className="rounded-xl bg-white p-6 shadow-sm transition hover:-translate-y-0.5 hover:shadow-md">

      <div className="flex items-start justify-between">

        <div>

          <p className="text-sm font-medium text-slate-500">
            {title}
          </p>

          <p
            className={`mt-2 text-3xl font-bold ${color}`}
          >
            {value}
          </p>

        </div>


        <div
          className={`flex h-10 w-10 items-center justify-center rounded-lg text-lg font-bold ${background} ${color}`}
        >
          {icon}
        </div>

      </div>

    </div>
  );
}


export default Stats;