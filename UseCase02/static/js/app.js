const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const chatMessages = document.getElementById("chat-messages");
const tableContent = document.getElementById("table-content");

function processResponse(response) {
  const codeRegex = /```([\s\S]*?)```/g;
  let formattedResponse = response.replace(codeRegex, (_, code) => {
      const escapedCode = code
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .trim();
      return `<pre><code>${escapedCode}</code></pre>`;
  });
  return formattedResponse;
}

function displayMessage(timestamp, role, message) {
  const messageElement = document.createElement("div");
  messageElement.classList.add("message");
  messageElement.innerHTML = `<span class="timestamp">${timestamp}</span> <span class="${role}">${role}: </span> ${message}`;
  chatMessages.appendChild(messageElement);
  // Re-highlight any code snippets in the new message
  Prism.highlightAllUnder(chatMessages);
}


function fetchAnswer(question) {
  fetch("/api/generate-text", {
      method: "POST",
      headers: {
          "Content-Type": "application/json",
      },
      body: JSON.stringify({ prompt: question }),
  })
      .then((response) => response.json())
      .then((data) => {
          const timestamp = data.timestamp;
          const formattedResponse = processResponse(data.response);
          displayMessage(timestamp, "assistant", formattedResponse);
          tableContent.innerHTML = data.table;
      })
      .catch((error) => {
          console.error("Error fetching answer:", error);
      });
}

sendBtn.addEventListener("click", () => {
  const question = userInput.value.trim();
  if (question) {
      const timestamp = new Date().toLocaleTimeString();
      displayMessage(timestamp, "user", question);
      fetchAnswer(question);
      userInput.value = "";
  }
});

userInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
      const question = userInput.value.trim();
      if (question) {
          const timestamp = new Date().toLocaleTimeString();
          displayMessage(timestamp, "user", question);
          fetchAnswer(question);
          userInput.value = "";
      }
  }
});
