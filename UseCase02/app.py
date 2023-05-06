import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import openai
from dotenv import load_dotenv
import os

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
CORS(app)

script_directory = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_directory)

df = pd.read_parquet('url_contents_embedded.parquet')

# Read the data from your DataFrame
embeddings = np.stack(df["ada_v2_embedding"].to_numpy())

# Define the function to generate embeddings using the same model as the DataFrame
def generate_embeddings(text, model="text-embedding-ada-002"):
    return openai.Embedding.create(input=[text], model=model)['data'][0]['embedding']

def get_question_embedding(question):
    return generate_embeddings(question)

# Define a function to compute cosine similarity
def get_most_similar_area(embedding, embeddings):
    embedding_array = np.array(embedding).reshape(1, -1)
    similarities = cosine_similarity(embedding_array, embeddings)
    most_similar_index = np.argmax(similarities)
    return df.iloc[most_similar_index]

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/api/generate-text", methods=["POST"])
def generate_text():
    data = request.json
    prompt = data.get("prompt")
    question_embedding = get_question_embedding(prompt)

    # Find the closest area in the DataFrame
    closest_area = get_most_similar_area(question_embedding, embeddings)

    # Send the question and the closest area to the LLM to get an answer
    messages = [
        {"role": "system", "content": "Assistant is a large language model trained by OpenAI."},
        {"role": "user", "content": f"Answer the following question based on this area of knowledge: {closest_area} delimit any code snippet with three backticks \nQuestion: {prompt}"}
    ]

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=messages,
    )
    
    answer = response.choices[0].message['content'].strip()
    table = closest_area.to_frame().transpose().to_html(classes='table table-bordered', index=False)
    result = f"Answer: {answer}"
    print(table)
    return jsonify({"response": result, "table": table})


if __name__ == "__main__":
    app.run(debug=True)