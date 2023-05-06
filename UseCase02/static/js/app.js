const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");
const chatMessages = document.getElementById("chat-messages");
const tableContent = document.getElementById("table-content");

function displayMessage(timestamp, role, message) {
    const messageElement = document.createElement("div");
    messageElement.classList.add("message");
    messageElement.innerHTML = `<span class="timestamp">${timestamp}</span> <span class="${role}">${role}: </span> ${message}`;
    chatMessages.appendChild(messageElement);
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
            const timestamp = new Date().toLocaleTimeString();
            displayMessage(timestamp, "assistant", data.response);
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
