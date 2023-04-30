class App extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        prompt: "",
        responses: [],
      };
      this.handleChange = this.handleChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
  }
  handleChange(event) {
    this.setState({ prompt: event.target.value });
  }

  async handleSubmit(event) {
    event.preventDefault();
    const { prompt } = this.state;

    try {
      const response = await axios.post("/api/generate-text", { prompt });
      this.setState((prevState) => ({
        responses: [...prevState.responses, { prompt, response: response.data.response }],
        prompt: "",
      }));
    } catch (error) {
      console.error("Error:", error);
    }
  }

  render() {
    const { prompt, responses } = this.state;

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
            <button className="btn btn-primary" type="submit">Submit</button>
          </div>
        </form>
        <div className="mt-4">
          {responses.map((item, index) => (
            <div key={index} className="mb-3">
              <strong>Prompt:</strong> {item.prompt}
              <br />
              <strong>Response:</strong> {item.response}
            </div>
          ))}
        </div>
      </div>
    );
  }
}

ReactDOM.render(<App />, document.getElementById("app"));
