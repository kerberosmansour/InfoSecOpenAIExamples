import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom';
import axios from 'axios';

const DataTable = ({ data }) => {
  if (!data || data.length === 0) {
    return null;
  }

  const header = Object.keys(data[0]);

  return (
    <table className="table table-bordered mt-2">
      <thead>
        <tr>
          {header.map((key, index) => (
            <th key={index}>{key}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {data.map((row, rowIndex) => (
          <tr key={rowIndex}>
            {Object.values(row).map((value, index) => (
              <td key={index}>{value}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const parseResponse = (response) => {
  const codeRegex = /```([\s\S]*?)```/g;
  const match = codeRegex.exec(response);
  if (match) {
    const code = match[1];
    return (
      <pre>
        <code className="language-javascript">{code}</code>
      </pre>
    );
  }
  return response;
};

const App = () => {
  const [prompt, setPrompt] = useState('');
  const [responses, setResponses] = useState([]);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    hljs.highlightAll();
  }, [responses]);

  const handleChange = (event) => {
    setPrompt(event.target.value);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    setIsLoading(true);

    try {
      const response = await axios.post('/api/generate-text', { prompt });
      const parser = new DOMParser();
      const tableHtml = parser.parseFromString(response.data.table, 'text/html');
      const tableData = Array.from(tableHtml.querySelectorAll('table tr'))
        .slice(1)
        .map((tr) => {
          const rowData = Array.from(tr.children).reduce((rowObj, td, colIndex) => {
            const key = tableHtml.querySelector(`table tr:first-child th:nth-child(${colIndex + 1})`).textContent.trim();
            rowObj[key] = td.textContent.trim();
            return rowObj;
          }, {});
          return rowData;
        });

      setResponses((prevState) => [
        ...prevState,
        {
          prompt,
          response: response.data.response,
          table: tableData,
          showTable: false,
        },
      ]);
      setPrompt('');
      setIsLoading(false);
    } catch (error) {
      console.error('Error:', error);
      setIsLoading(false);
    }
  };

  const toggleTable = (index) => {
    setResponses((prevResponses) =>
      prevResponses.map((response, i) => {
        if (i === index) {
          return { ...response, showTable: !response.showTable };
        }
        return response;
      })
    );
  };

  return (
    <div>
      {/* Form to submit prompts */}
      <form onSubmit={handleSubmit}>
        <div className="input-group mt-3">
          <input
            type="text"
            className="form-control"
            placeholder="Enter your prompt"
            value={prompt}
            onChange={handleChange}
          />
          <button className="btn btn-primary" type="submit" disabled={isLoading}>
            Submit
          </button>
        </div>
      </form>
      {/* Loading spinner */}
      {isLoading && <div className="mt-3 spinner"></div>}
      {/* List of responses */}
      <div className="mt-4">
        {responses.slice(0).reverse().map((item, index) => (
          <div key={index} className="mb-3">
            <div className="alert alert-primary" role="alert">
              <strong>User:</strong> {item.prompt} <br />
              <small>{item.timestamp}</small>
            </div>
            <div className="alert alert-success" role="alert">
              {parseResponse(item.response)}
            </div>
            {/* Toggle table button */}
            <button
              className="btn btn-link p-0"
              onClick={() => toggleTable(index)}
            >
              {item.showTable ? "Hide table" : "Show table"}
            </button>
            {/* Conditional rendering of the table */}
            {item.showTable && <DataTable data={item.table} />}
          </div>
        ))}
      </div>
    </div>
  );
};

ReactDOM.render(<App />, document.getElementById('app'));

