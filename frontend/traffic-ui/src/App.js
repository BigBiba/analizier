import React, { useEffect, useState, useCallback } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  LineChart,
  Line,
} from "recharts";

function App() {
  const [data, setData] = useState([]);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");

  // Fetch data from server
  const fetchData = useCallback(() => {
    let url = "http://127.0.0.1:8080/api/traffic";

    if (filterIP.trim() !== "") {
      url += `?source_ip=${encodeURIComponent(filterIP)}`;
    }

    fetch(url)
      .then((res) => res.json())
      .then((items) => setData(items));
  }, [filterIP]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // WebSocket for live updates
  useEffect(() => {
    const ws = new WebSocket("ws://127.0.0.1:8080/ws");

    ws.onopen = () => console.log("WS connected");

    ws.onmessage = (event) => {
      const newData = JSON.parse(event.data);

      setData((prev) => {
        const exists = prev.find((item) => item.id === newData.id);
        if (exists) return prev;
        return [...prev, newData]; // добавляем в конец
      });
    };

    ws.onerror = (e) => console.error("WS error", e);
    ws.onclose = () => console.log("WS disconnected");

    return () => ws.close();
  }, []);

  // Локальная фильтрация по IP и аномалиям
  const filteredData = data.filter((item) => {
    return (
      (filterIP === "" ||
        item.source_ip.includes(filterIP) ||
        item.destination_ip.includes(filterIP)) &&
      (filterAnomaly === "" || item.anomaly_type === filterAnomaly)
    );
  });

  // 1. Трафик по Source IP
  const trafficByIP = Object.values(
    filteredData.reduce((acc, cur) => {
      acc[cur.source_ip] = acc[cur.source_ip] || { source_ip: cur.source_ip, volume: 0 };
      acc[cur.source_ip].volume += cur.traffic_volume;
      return acc;
    }, {})
  );

  // 2. Количество аномалий по типу
  const anomaliesCount = Object.values(
    filteredData.reduce((acc, cur) => {
      if (cur.anomaly_type && cur.anomaly_type !== "None") {
        acc[cur.anomaly_type] = acc[cur.anomaly_type] || { anomaly_type: cur.anomaly_type, count: 0 };
        acc[cur.anomaly_type].count += 1;
      }
      return acc;
    }, {})
  );

  // 3. Трафик по времени
  const trafficByTime = Object.values(
    filteredData.reduce((acc, cur) => {
      const time = cur.timestamp.split(" ")[1].slice(0, 5); // Часы:минуты
      acc[time] = acc[time] || { time, volume: 0 };
      acc[time].volume += cur.traffic_volume;
      return acc;
    }, {})
  );

  return (
    <div style={{ padding: "20px" }}>
      <h2>Network Traffic</h2>

      {/* Фильтры */}
      <div style={{ marginBottom: "20px" }}>
        <input
          placeholder="Filter by IP"
          value={filterIP}
          onChange={(e) => setFilterIP(e.target.value)}
          style={{ marginRight: "10px" }}
        />

        <select
          value={filterAnomaly}
          onChange={(e) => setFilterAnomaly(e.target.value)}
        >
          <option value="">All anomalies</option>
          <option value="None">None</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Malware">Malware</option>
        </select>

        <button onClick={fetchData} style={{ marginLeft: "10px" }}>
          Search
        </button>
      </div>

      {/* Таблица */}
      <table border="1" cellPadding="10" style={{ marginTop: "20px" }}>
        <thead>
          <tr>
            <th>ID</th>
            <th>Flow</th>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Protocol</th>
            <th>Src Port</th>
            <th>Dst Port</th>
            <th>Flags</th>
            <th>IP Version</th>
            <th>Volume</th>
            <th>Anomaly</th>
          </tr>
        </thead>
        <tbody>
          {filteredData.map((item) => (
            <tr key={item.id}>
              <td>{item.id}</td>
              <td>{item.flow_id}</td>
              <td>{item.timestamp}</td>
              <td>{item.source_ip}</td>
              <td>{item.destination_ip}</td>
              <td>{item.protocol}</td>
              <td>{item.source_port}</td>
              <td>{item.destination_port}</td>
              <td>{item.flags}</td>
              <td>{item.ip_version}</td>
              <td>{item.traffic_volume}</td>
              <td>{item.anomaly_type}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Графики */}
      <div style={{ display: "flex", gap: "40px", marginTop: "40px" }}>
        {/* Трафик по IP */}
        <BarChart width={400} height={250} data={trafficByIP}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="source_ip" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="volume" fill="#8884d8" />
        </BarChart>

        {/* Аномалии по типу */}
        <BarChart width={400} height={250} data={anomaliesCount}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="anomaly_type" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Bar dataKey="count" fill="#82ca9d" />
        </BarChart>

        {/* Трафик по времени */}
        <LineChart width={400} height={250} data={trafficByTime}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis />
          <Tooltip />
          <Legend />
          <Line type="monotone" dataKey="volume" stroke="#ff7300" />
        </LineChart>
      </div>
    </div>
  );
}

export default App;