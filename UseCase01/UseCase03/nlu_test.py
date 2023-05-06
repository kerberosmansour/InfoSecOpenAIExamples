import spacy
import datetime
import pytz
from pytz import country_timezones, timezone

nlp = spacy.load("en_core_web_sm")

def nlu_time_query(user_input):
    doc = nlp(user_input)
    location = None

    for ent in doc.ents:
        if ent.label_ == "GPE":
            location = ent.text

    if "time" in user_input.lower():
        if location:
            return get_time_in_location(location)
        else:
            return get_local_time()

    return "Sorry, I couldn't understand your query. Please try again."

def get_local_time():
    current_time = datetime.datetime.now()
    return current_time.strftime("%Y-%m-%d %H:%M:%S")

def get_time_in_location(location):
    try:
        country_code = None
        for code, country_name in list(pytz.country_names.items()):
            if location.lower() in country_name.lower():
                country_code = code
                break

        if country_code:
            tz = country_timezones[country_code][0]
            current_time = datetime.datetime.now(timezone(tz))
            return current_time.strftime("%Y-%m-%d %H:%M:%S")
        else:
            return f"Sorry, I couldn't find the timezone for {location}."
    except Exception as e:
        return f"Sorry, an error occurred while processing your request: {str(e)}"

# Example usage:
user_input = "I wonder, and I am really wondering herem, what's the current time in Egypt?"
print(nlu_time_query(user_input))
