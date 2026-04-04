import React, { useEffect, useState, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  LineChart, Line,
} from "recharts";

function App() {
  const [data, setData] = useState([]);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [file, setFile] = useState(null);

  const itemsPerPage = 20;

  // Цвета строк
  const getRowStyle = (anomaly) => {
    switch (anomaly) {
      case "Malware":
        return { backgroundColor: "#ffcccc" };
      case "Suspicious":
        return { backgroundColor: "#fff3cd" };
      case "None":
        return { backgroundColor: "#e6ffed" };
      default:
        return {};
    }
  };

  // Загрузка файла
  const handleUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    await fetch("http://127.0.0.1:8080/api/upload", {
      method: "POST",
      body: formData,
    });

    fetchData();
  };

  // Получение данных
  const fetchData = useCallback(() => {
    let url = `http://127.0.0.1:8080/api/traffic?page=${currentPage}&limit=20`;

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

  // WebSocket
  useEffect(() => {
    const ws = new WebSocket("ws://127.0.0.1:8080/ws");

    ws.onmessage = (event) => {
      const newData = JSON.parse(event.data);

      setData((prev) => {
        if (prev.find((i) => i.id === newData.id)) return prev;
        return [...prev, newData];
      });
    };

    return () => ws.close();
  }, []);

  // Фильтрация
  const filteredData = data.filter((item) => {
    return (
      (filterIP === "" ||
        item.source_ip.includes(filterIP) ||
        item.destination_ip.includes(filterIP)) &&
      (filterAnomaly === "" || item.anomaly_type === filterAnomaly)
    );
  });

  // Сброс страницы при фильтрах
  useEffect(() => {
    setCurrentPage(1);
  }, [filterIP, filterAnomaly]);

  // Пагинация
  const totalPages = Math.ceil(filteredData.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedData = filteredData.slice(startIndex, startIndex + itemsPerPage);

  // Графики
  const trafficByIP = Object.values(
    filteredData.reduce((acc, cur) => {
      acc[cur.source_ip] = acc[cur.source_ip] || { source_ip: cur.source_ip, volume: 0 };
      acc[cur.source_ip].volume += cur.traffic_volume;
      return acc;
    }, {})
  );

  const anomaliesCount = Object.values(
    filteredData.reduce((acc, cur) => {
      if (cur.anomaly_type && cur.anomaly_type !== "None") {
        acc[cur.anomaly_type] = acc[cur.anomaly_type] || { anomaly_type: cur.anomaly_type, count: 0 };
        acc[cur.anomaly_type].count += 1;
      }
      return acc;
    }, {})
  );

  const trafficByTime = Object.values(
    filteredData.reduce((acc, cur) => {
      const time = cur.timestamp.split(" ")[1].slice(0, 5);
      acc[time] = acc[time] || { time, volume: 0 };
      acc[time].volume += cur.traffic_volume;
      return acc;
    }, {})
  );

  return (
    <div style={{ padding: "20px" }}>
      <h2>Network Traffic</h2>

      {/* Upload */}
      <div style={{ marginBottom: "20px" }}>
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={handleUpload}>Upload PCAP</button>
      </div>

      {/* Фильтры */}
      <div style={{ marginBottom: "20px" }}>
        <input
          placeholder="Filter by IP"
          value={filterIP}
          onChange={(e) => setFilterIP(e.target.value)}
        />

        <select
          value={filterAnomaly}
          onChange={(e) => setFilterAnomaly(e.target.value)}
          style={{ marginLeft: "10px" }}
        >
          <option value="">All</option>
          <option value="None">None</option>
          <option value="Suspicious">Suspicious</option>
          <option value="Malware">Malware</option>
        </select>
      </div>

      {/* Пагинация */}
      <div>
        <button disabled={currentPage === 1}
          onClick={() => setCurrentPage(p => p - 1)}>Prev</button>

        <span style={{ margin: "0 10px" }}>
          {currentPage} / {totalPages || 1}
        </span>

        <button disabled={currentPage >= totalPages}
          onClick={() => setCurrentPage(p => p + 1)}>Next</button>
      </div>

      {/* Таблица */}
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
            <tr key={item.id} style={getRowStyle(item.anomaly_type)}>
              <td>{item.id}</td>
              <td>{item.flow_id}</td>
              <td>{item.timestamp}</td>
              <td>{item.source_ip}</td>
              <td>{item.destination_ip}</td>
              <td>{item.source_port}</td>
              <td>{item.destination_port}</td>
              <td>{item.flags}</td>
              <td>{item.traffic_volume}</td>
              <td>{item.anomaly_type}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Графики */}
      <div style={{ display: "flex", gap: "40px", marginTop: "40px" }}>
        <BarChart width={350} height={250} data={trafficByIP}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="source_ip" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="volume" fill="#8884d8" />
        </BarChart>

        <BarChart width={350} height={250} data={anomaliesCount}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="anomaly_type" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="count" fill="#82ca9d" />
        </BarChart>

        <LineChart width={350} height={250} data={trafficByTime}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="volume" stroke="#ff7300" />
        </LineChart>
      </div>
    </div>
  );
}

export default App;