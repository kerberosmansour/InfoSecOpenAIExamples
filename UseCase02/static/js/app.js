class DataTable extends React.Component {
  render() {
    const { data } = this.props;

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
  }
}

class App extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      prompt: "",
      responses: [],
      isLoading: false,
    };
    this.handleChange = this.handleChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  componentDidMount() {
    hljs.highlightAll();
  }

  componentDidUpdate() {
    hljs.highlightAll();
  }

  handleChange(event) {
    this.setState({ prompt: event.target.value });
  }

  renderCodeSnippet(code) {
    return <pre><code className="language-javascript">{code}</code></pre>;
  }

  async handleSubmit(event) {
    event.preventDefault();
    const { prompt } = this.state;

    this.setState({ isLoading: true });

    try {
      const response = await axios.post("/api/generate-text", { prompt });
      const parser = new DOMParser();
      const tableHtml = parser.parseFromString(response.data.table, "text/html");
      const tableData = Array.from(tableHtml.querySelectorAll("table tr")).slice(1).map((tr) => {
        const rowData = Array.from(tr.children).reduce((rowObj, td, colIndex) => {
          const key = tableHtml.querySelector(`table tr:first-child th:nth-child(${colIndex + 1})`).textContent.trim();
          rowObj[key] = td.textContent.trim();
          return rowObj;
        }, {});
        return rowData;
      });

      this.setState((prevState) => ({
        responses: [
          ...prevState.responses,
          {
            prompt,
            response: response.data.response,
            table: tableData,
          },
        ],
        prompt: "",
        isLoading: false,
      }));
    } catch (error) {
      console.error("Error:", error);
      this.setState({ isLoading: false });
    }
  }
  render() {
    const { prompt, responses, isLoading } = this.state;
  
    return (
      <div>
        <form onSubmit={this.handleSubmit}>
          <div className="input-group mt-3">
            <input
              type="text"
              className="form-control"
              placeholder="Enter your prompt"
              value={prompt}
              onChange={this.handleChange}
            />
            <button className="btn btn-primary" type="submit" disabled={isLoading}>
              Submit
            </button>
          </div>
        </form>
        {isLoading && <div className="mt-3 spinner"></div>}
        <div className="mt-4">
          {responses.slice(0).reverse().map((item, index) => (
            <div key={index} className="mb-3">
              <div className="alert alert-primary" role="alert">
                <strong>User:</strong> {item.prompt} <br />
                <small>{item.timestamp}</small>
              </div>
              <div className="alert alert-success" role="alert">
                {this.renderCodeSnippet(item.response)}
              </div>
              <DataTable data={item.table} />
            </div>
          ))}
        </div>
      </div>
    );
  }
  

}


ReactDOM.render(<App />, document.getElementById("app"));
