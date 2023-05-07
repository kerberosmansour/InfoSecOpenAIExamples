const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const chatMessages = document.getElementById("chat-messages");
const tableContent = document.getElementById("table-content");

function processResponse(response) {
  const codeRegex = /```([\s\S]*?)```/g;
  let formattedResponse = response.replace(codeRegex, (_, code) => {
    const language = (_.match(/```(.*)\n/) || [])[1] || "none";
    const escapedCode = code
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .trim();
    return `<pre><code class="language-${language}">${escapedCode}</code></pre>`;
  });
  return formattedResponse;
}

function displayMessage(timestamp, role, message, data) {
  const messageElement = document.createElement("div");
  messageElement.classList.add("message", role);
  messageElement.innerHTML = `
    <div class="message-card">
      <span class="timestamp">${timestamp}</span>
      <span class="${role}-label">${role}: </span>
      ${message}
    </div>`;
  chatMessages.appendChild(messageElement);

  if (data) {
    const tableElement = document.createElement("div");
    tableElement.classList.add("table-responsive", "bg-light", "shadow", "p-3", "rounded", "mt-3");
  
    const link = data[0].link;
    const text = `*Reference: The above answer was based on the ${data[2].link} section of ${data[1].link}`;
  
    const anchor = document.createElement("a");
    anchor.href = link;
    anchor.target = "_blank";
    anchor.textContent = text;
  
    tableElement.appendChild(anchor);
    chatMessages.appendChild(tableElement);
  }

  // Re-highlight any code snippets in the new message
  Prism.highlightAllUnder(chatMessages);
}



function fetchAnswer(question) {
  // Add the spinner next to the send button
  sendBtn.insertAdjacentHTML(
    "afterend",
    '<div id="loading-spinner" class="spinner-container text-center mt-3"><div class="spinner"></div></div>'
  );

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

      // Hide the loading spinner and remove it from the DOM
      const spinner = document.getElementById("loading-spinner");
      spinner.classList.add("d-none");
      spinner.remove();

      displayMessage(timestamp, "assistant", formattedResponse, data.table);
    })
    .catch((error) => {
      console.error("Error fetching answer:", error);

      // Hide the loading spinner and remove it from the DOM in case of an error
      const spinner = document.getElementById("loading-spinner");
      spinner.classList.add("d-none");
      spinner.remove();
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

