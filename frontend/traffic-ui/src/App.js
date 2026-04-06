import React, { useEffect, useState, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  LineChart, Line,
} from "recharts";

function App() {
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [file, setFile] = useState(null);

  const itemsPerPage = 20;

  // Извлекаем тип аномалии из массива anomalies
  const getAnomaly = (item) => {
    if (item?.anomalies?.length > 0) {
      return item.anomalies[0].anomaly_type;
    }
    return "None";
  };

  const getRowStyle = (anomaly) => {
    switch (anomaly) {
      case "DoS/DDoS Attack":
        return { backgroundColor: "#ff4d4d" };

      case "Network Overload":
        return { backgroundColor: "#ff944d" };

      case "Network/Port Scanning":
        return { backgroundColor: "#ffc107" };

      case "Worm Activity":
        return { backgroundColor: "#ff6666" };

      case "Point-to-Multipoint":
        return { backgroundColor: "#66ccff" };

      case "Flow Switching":
        return { backgroundColor: "#c084fc" };

      case "Confirmed Virus Activity":
        return { backgroundColor: "#cc0000", color: "white" };

      case "None":
      case "":
      case null:
      case undefined:
        return { backgroundColor: "#e6ffed" };

      default:
        return { backgroundColor: "#f0f0f0" };
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });

    fetchData();
  };

  const fetchData = useCallback(() => {
    let url = `/api/traffic?page=${currentPage}&limit=${itemsPerPage}`;

    if (filterIP.trim() !== "") {
      url += `&source_ip=${encodeURIComponent(filterIP)}`;
    }

    fetch(url)
      .then((res) => res.json())
      .then((result) => {
        setData(result.data || []);
        setTotalItems(result.total || 0);
      });
  }, [filterIP, currentPage]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.host || "localhost:8080";
    const ws = new WebSocket(`${wsProtocol}//${wsHost}/ws`);

    ws.onmessage = (event) => {
      const newData = JSON.parse(event.data);

      setData((prev) => {
        if (prev.find((i) => i.id === newData.id)) return prev;
        return [...prev, newData];
      });
    };

    return () => ws.close();
  }, []);

  const filteredData = data.filter((item) => {
    return (
      (filterIP === "" ||
        item.source_ip?.includes(filterIP) ||
        item.destination_ip?.includes(filterIP)) &&
      (filterAnomaly === "" || getAnomaly(item) === filterAnomaly)
    );
  });

  const totalPages = Math.ceil(totalItems / itemsPerPage);

  // Пагинация уже пришла с бэкенда — данные уже paginated
  const paginatedData = filteredData;

  const trafficByIP = Object.values(
    filteredData.reduce((acc, cur) => {
      const ip = cur.source_ip || "unknown";

      if (!acc[ip]) {
        acc[ip] = { source_ip: ip, volume: 0 };
      }

      acc[ip].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );

  const anomaliesCount = Object.values(
    filteredData.reduce((acc, cur) => {
      const anomaly =
        cur?.anomalies?.[0]?.anomaly_type;

      if (!anomaly) return acc;

      if (!acc[anomaly]) {
        acc[anomaly] = {
          anomaly_type: anomaly,
          count: 0,
        };
      }

      acc[anomaly].count += 1;

      return acc;
    }, {})
  );

  const trafficByTime = Object.values(
    filteredData.reduce((acc, cur) => {
      const time = (cur.timestamp || "").slice(11, 16);

      if (!time) return acc;

      if (!acc[time]) {
        acc[time] = { time, volume: 0 };
      }

      acc[time].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );
  console.log("SAMPLE ITEM:", anomaliesCount.length);
  console.log(getAnomaly(data[0]));
  console.log("RAW ITEM:", data[0]);
  console.log(anomaliesCount.length)
  return (
    <div style={{ padding: "20px" }}>
      <h2>Network Traffic</h2>

      {/* Upload */}
      <div style={{ marginBottom: "20px" }}>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={handleUpload}>Upload PCAP</button>
      </div>

      {/* Filters */}
      <div style={{ marginBottom: "20px" }}>
        <input
          placeholder="Filter by IP"
          value={filterIP}
          onChange={(e) => setFilterIP(e.target.value)}
        />

        <select
          value={filterAnomaly}
          onChange={(e) => setFilterAnomaly(e.target.value)}
        >
          <option value="">All</option>

          <option value="DoS/DDoS Attack">DoS/DDoS</option>
          <option value="Network Overload">Overload</option>
          <option value="Network/Port Scanning">Port Scanning</option>
          <option value="Worm Activity">Worm</option>
          <option value="Confirmed Virus Activity">Virus</option>
          <option value="Point-to-Multipoint">P2MP</option>
          <option value="Flow Switching">Flow Switching</option>
        </select>
      </div>

      {/* Pagination */}
      <div>
        <button disabled={currentPage === 1}
          onClick={() => setCurrentPage(p => p - 1)}>Prev</button>

        <span style={{ margin: "0 10px" }}>
          {currentPage} / {totalPages || 1}
        </span>

        <button disabled={currentPage >= totalPages}
          onClick={() => setCurrentPage(p => p + 1)}>Next</button>
      </div>

      {/* Table */}
      <table border="1" cellPadding="8" style={{ marginTop: "20px" }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Flow</th>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Src Port</th>
            <th>Dst Port</th>
            <th>Flags</th>
            <th>Volume</th>
            <th>Anomaly</th>
          </tr>
        </thead>

        <tbody>
          {paginatedData.map((item) => (
            <tr
              key={item.id}
              style={getRowStyle(getAnomaly(item))}
            >
              <td>{item.id}</td>
              <td>{item.flow_id}</td>
              <td>{item.timestamp}</td>
              <td>{item.source_ip}</td>
              <td>{item.destination_ip}</td>
              <td>{item.source_port}</td>
              <td>{item.destination_port}</td>
              <td>{item.flags}</td>
              <td>{item.traffic_volume}</td>
              <td>{getAnomaly(item)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Charts */}
      <div style={{ display: "flex", gap: "40px", marginTop: "40px" }}>

        <BarChart width={350} height={250} data={trafficByIP}
          margin={{ top: 20, right: 30, left: 60, bottom: 20 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="source_ip" />
          <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
          <Tooltip />
          <Bar dataKey="volume" />
        </BarChart>

        <BarChart width={350} height={250} data={anomaliesCount}
          margin={{ top: 20, right: 30, left: 60, bottom: 20 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="anomaly_type" />
          <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
          <Tooltip />
          <Bar dataKey="count" />
        </BarChart>

        <LineChart width={350} height={250} data={trafficByTime}
          margin={{ top: 20, right: 30, left: 60, bottom: 20 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
          <Tooltip />
          <Line type="monotone" dataKey="volume" />
        </LineChart>

      </div>
    </div>
  );
}

export default App;