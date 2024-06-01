import os
import requests
import feedparser
import tweepy
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
import anthropic
from bs4 import BeautifulSoup

from dotenv import load_dotenv
import os

load_dotenv()

# Access the keys
google_api_key = os.getenv('GOOGLE_API_KEY')
claude_api_key = os.getenv('CLAUDE_API_KEY')
news_api_key = os.getenv('NEWS_API_KEY')
twitter_api_key = os.getenv('TWITTER_API_KEY')
twitter_api_secret_key = os.getenv('TWITTER_API_SECRET_KEY')
twitter_access_token = os.getenv('TWITTER_ACCESS_TOKEN')
twitter_access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET')

genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')
anthropic_client = anthropic.Client(api_key=CLAUDE_API_KEY)

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    searches = db.relationship('Search', backref='user', lazy=True)

# Search model
class Search(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    query = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    custom_sources = db.Column(db.String(500), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

def extract_text_from_url(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        text_data = "".join([p.get_text() for p in soup.find_all('p')])
        return text_data
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL data: {e}")
        return None

def search_articles_with_claude(name, articles):
    keyword = name.lower()
    relevant_articles = []
    for article in articles:
        content = article.get('content', '') or article.get('description', '')
        if keyword in content.lower():
            relevant_articles.append(article)
    return relevant_articles[:5]

def summarize_article_with_claude(article):
    url = article.get('url', '#')
    title = article.get('title', 'No Title')
    return f"<strong><a href='{url}' target='_blank'>{title}</a></strong><button class='summarize-btn' data-url='{url}'>Summarize This</button><br>"

def get_news_with_claude(name, api_key):
    url = f"https://newsapi.org/v2/everything?q={name}&apiKey={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        articles = response.json().get('articles', [])
        filtered_articles = search_articles_with_claude(name, articles)
        summaries = [summarize_article_with_claude(article) for article in filtered_articles]
        return '<br><br>'.join(summaries)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching news data: {e}")
        return "Error fetching news data."

def get_wikipedia_summary(name):
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{name}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get('extract', 'No summary available.')
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Wikipedia page not found for {name}")
            return "No Wikipedia summary available."
        else:
            print(f"Error fetching Wikipedia data: {e}")
            return "Error fetching Wikipedia data."

def get_twitter_feed(username):
    try:
        auth = tweepy.OAuth1UserHandler(TWITTER_API_KEY, TWITTER_API_SECRET_KEY, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_TOKEN_SECRET)
        api = tweepy.API(auth)
        tweets = api.user_timeline(screen_name=username, count=10, tweet_mode="extended")
        return '<br><br>'.join([tweet.full_text for tweet in tweets])
    except tweepy.TweepyException as e:
        if '403' in str(e):
            print(f"Error fetching Twitter data for {username}: {e}")
            return "Access to Twitter data is restricted. Please check your API access level."
        else:
            print(f"Error fetching Twitter data: {e}")
            return "Error fetching Twitter data."

def get_custom_data_sources(custom_sources):
    summaries = []
    for source in custom_sources.split(','):
        if source.startswith('http'):
            feed = feedparser.parse(source.strip())
            for entry in feed.entries:  # No limit to entries per source
                summaries.append(entry.summary)
    return '<br><br>'.join(summaries)

def summarize_with_gemini(text):
    prompt = f"Please summarize the following text in bullet points with headings in bold:\n\n{text}\n\nSummary in bullet points:"
    response = model.generate_content(prompt)
    return response.text.strip()


def summarize_with_gemini_inpara(text):
    prompt = f"Please summarize the following text in one paragraph\n\n{text}\n\nSummary in paragraph:"
    response = model.generate_content(prompt)
    return response.text.strip()

def generate_profile_with_gemini(name):
    prompt = f"Provide a detailed profile of {name} with headings in bold and in bullet points:"
    response = model.generate_content(prompt)
    return response.text.strip()

def process_text_for_html(text):
    processed_text = text.replace('**', '<strong>').replace('*', '').replace('<strong>', '</strong>').replace('\n', '<br><br>')
    return processed_text

def get_combined_profile(name, custom_sources=''):
    try:
        profile_summary = generate_profile_with_gemini(name)
    except Exception as e:
        profile_summary = "Error generating profile."
        print(f"Error generating profile: {e}")

    try:
        news_summary = get_news_with_claude(name, NEWS_API_KEY)
    except Exception as e:
        news_summary = "Error fetching news summary."
        print(f"Error fetching news summary: {e}")

    try:
        wikipedia_summary = get_wikipedia_summary(name)
    except Exception as e:
        wikipedia_summary = "Error fetching Wikipedia summary."
        print(f"Error fetching Wikipedia summary: {e}")

    try:
        twitter_summary = get_twitter_feed(name)
    except Exception as e:
        twitter_summary = "Error fetching Twitter feed."
        print(f"Error fetching Twitter feed: {e}")

    try:
        custom_summary = get_custom_data_sources(custom_sources)
    except Exception as e:
        custom_summary = "Error fetching custom data sources."
        print(f"Error fetching custom data sources: {e}")

    try:
        combined_text = f"{profile_summary}\n{news_summary}\n{wikipedia_summary}\n{twitter_summary}\n{custom_summary}"
        summarized_combined_text = summarize_with_gemini(combined_text)
    except Exception as e:
        summarized_combined_text = "Error summarizing combined text."
        print(f"Error summarizing combined text: {e}")

    combined_summary = {
        "profile_summary": process_text_for_html(profile_summary),
        "news_summary": process_text_for_html(news_summary),
        "wikipedia_summary": process_text_for_html(wikipedia_summary),
        "twitter_summary": process_text_for_html(twitter_summary),
        "custom_summary": process_text_for_html(custom_summary),
        "summarized_combined_text": process_text_for_html(summarized_combined_text)
    }
    return combined_summary

@app.route('/profile', methods=['POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form['name']
        custom_sources = request.form.get('custom_sources', '')
        profile = get_combined_profile(name, custom_sources)
        return render_template('profile.html', profile=profile, name=name)

@app.route('/summarize', methods=['POST'])
def summarize():
    if request.method == 'POST':
        data = request.get_json()
        url = data['url']
        text = extract_text_from_url(url)
        if text:
            summary = summarize_with_gemini_inpara(text)
            return jsonify({'summary': summary})
        else:
            return jsonify({'summary': 'Error fetching or summarizing the article.'}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
