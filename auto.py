import threading
import tkinter as tk
from tkinter import ttk, messagebox
import requests
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from urllib.parse import urlparse, urlencode, unquote_plus

BASE_URL = "https://coinswitch.co"
API_KEY = ""          # Replace this with your CoinSwitch API key
SECRET_KEY = ""  
EXCHANGE = "coinswitchx"          # wazir,c1c2

# Whitelist of reliable, high liquidity INR pairs
WHITELIST_PAIRS = [
    "BTC/INR",
    "ETH/INR",
    "XRP/INR",
    "BNB/INR",
    "ADA/INR",
    "DOGE/INR",
    "SOL/INR",
    "MATIC/INR",
    "DOT/INR",
    "SHIB/INR","BAT/INR","BNB/INR","CHR/INR","CRV/INR","ETH/INR",
    "FTM/INR","LRC/INR","LTC/INR","MKR/INR","OGN/INR",
    "OMG/INR","REQ/INR","SXP/INR","TRX/INR","UMA/INR",
    "UNI/INR","XLM/INR","XRP/INR","YFI/INR","ZRX/INR",
    "BICO/INR","COMP/INR","COTI/INR","DOGE/INR","GALA/INR",
    "IOST/INR","PEPE/INR","SAND/INR","USDT/INR","YFII/INR",
    "1INCH/INR","ALICE/INR","JASMY/INR",
]

# --- API Authentication & Signature ---
def get_server_time():
    try:
        r = requests.get(f"{BASE_URL}/trade/api/v2/time", headers={"Content-Type": "application/json"}, timeout=5)
        return str(r.json()["serverTime"])
    except Exception:
        return str(int(time.time() * 1000))  # fallback epoch time

def generate_signature(method, endpoint, params_payload, epoch_time, secret_key):
    import json
    unquote_endpoint = endpoint
    if method == "GET" and params_payload:
        endpoint += ('&', '?')[urlparse(endpoint).query == ''] + urlencode(params_payload)
        unquote_endpoint = unquote_plus(endpoint)
        message = method + unquote_endpoint + epoch_time
    else:
        message = method + unquote_endpoint + json.dumps(params_payload, separators=(',', ':'), sort_keys=True) + epoch_time
    request_bytes = message.encode('utf-8')
    secret_key_bytes = bytes.fromhex(secret_key)
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key_bytes)
    sig_bytes = sk.sign(request_bytes)
    return sig_bytes.hex()

def get_headers(method, endpoint, params_payload):
    epoch_time = get_server_time()
    sig = generate_signature(method, endpoint, params_payload, epoch_time, SECRET_KEY)
    return {
        "Content-Type": "application/json",
        "X-AUTH-SIGNATURE": sig,
        "X-AUTH-APIKEY": API_KEY,
        "X-AUTH-EPOCH": epoch_time
    }

def safe_request(method, url, headers=None, params=None, json_payload=None, retries=3):
    for attempt in range(retries):
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, params=params, timeout=8)
            else:
                resp = requests.post(url, headers=headers, json=json_payload, timeout=8)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            if attempt == retries - 1:
                raise e
            time.sleep(1)
    raise Exception("Failed after retries")

# --- Core API ---
def fetch_precision(symbol):
    endpoint = "/trade/api/v2/exchangePrecision"
    payload = {"exchange": EXCHANGE, "symbol": symbol}
    headers = get_headers("POST", endpoint, payload)
    url = BASE_URL + endpoint
    resp = safe_request("POST", url, headers, json_payload=payload)
    base_prec = resp["data"][EXCHANGE][symbol]['base']
    quote_prec = resp["data"][EXCHANGE][symbol]['quote']
    return base_prec, quote_prec

def fetch_price_with_retry(symbol, max_retries=5, delay=3):
    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            endpoint = "/trade/api/v2/24hr/ticker"
            params = {"symbol": symbol, "exchange": EXCHANGE}
            headers = get_headers("GET", endpoint, params)
            url = BASE_URL + endpoint
            data = safe_request("GET", url, headers, params).get("data", {})
            if symbol in data:
                price = float(data[symbol].get("lastPrice", 0))
                if price > 0:
                    return price
                else:
                    raise ValueError("Zero or invalid price")
            else:
                raise ValueError("Missing price data")
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                time.sleep(delay)
            else:
                raise last_exception

def place_order(side, symbol, qty, price):
    endpoint = "/trade/api/v2/order"
    payload = {
        "side": side,
        "symbol": symbol,
        "type": "limit",
        "quantity": qty,
        "price": price,
        "exchange": EXCHANGE
    }
    headers = get_headers("POST", endpoint, payload)
    url = BASE_URL + endpoint
    return safe_request("POST", url, headers, json_payload=payload)

# --- Trading logic ---
def select_best_from_whitelist(log_fn):
    best_coin = None
    best_change = -float('inf')
    endpoint = "/trade/api/v2/24hr/all-pairs/ticker"
    params = {"exchange": EXCHANGE}
    headers = get_headers("GET", endpoint, params)
    url = BASE_URL + endpoint
    try:
        tickers = safe_request("GET", url, headers, params).get("data", {})
    except Exception as e:
        log_fn(f"Error fetching ticker data: {e}")
        return None

    for sym in WHITELIST_PAIRS:
        ticker = tickers.get(sym)
        if ticker:
            try:
                price = fetch_price_with_retry(sym)
                change = float(ticker.get('percentageChange', 0))
                if change > best_change:
                    best_coin = sym
                    best_change = change
            except Exception as e:
                log_fn(f"Skipping {sym} due to price issue: {e}")
                continue
    if best_coin:
        log_fn(f"Selected best coin from whitelist: {best_coin} with 24h change {best_change:.2f}%")
    else:
        log_fn("No suitable coin with valid price found in whitelist.")
    return best_coin

def calculate_quantity(invest_amount, price, base_prec):
    return round(invest_amount / price, base_prec)

bot_running = False

def place_order_with_retry(side, symbol, qty, price, log_fn, max_retries=5):
    for attempt in range(1, max_retries + 1):
        try:
            resp = place_order(side, symbol, qty, price)
            log_fn(f"Order placed (attempt {attempt}): {resp}")
            return resp
        except Exception as e:
            if attempt == max_retries:
                log_fn(f"Failed to place order after {max_retries} attempts: {e}")
                raise e
            log_fn(f"Order attempt {attempt} failed: {e}, retrying...")
            time.sleep(2)
    return None

def manage_position(symbol, qty, entry_price, log_fn, stop_loss_pct=0.985, take_profit_pct=1.03):
    global bot_running
    while bot_running:
        try:
            current_price = fetch_price_with_retry(symbol)
            if current_price >= entry_price * take_profit_pct:
                log_fn(f"Take profit triggered for {symbol} at ₹{current_price:.2f}")
                place_order_with_retry("sell", symbol, qty, current_price, log_fn)
                break
            elif current_price <= entry_price * stop_loss_pct:
                log_fn(f"Stop loss triggered for {symbol} at ₹{current_price:.2f}")
                place_order_with_retry("sell", symbol, qty, current_price, log_fn)
                break
            time.sleep(30)
        except Exception as e:
            log_fn(f"Error managing position: {e}")
            time.sleep(30)

def trading_bot_loop(invest_amount, log_fn):
    global bot_running
    while bot_running:
        try:
            symbol = select_best_from_whitelist(log_fn)
            if not symbol:
                log_fn("No suitable coin found, retrying in 5 minutes...")
                time.sleep(300)
                continue
            price = fetch_price_with_retry(symbol)
            base_prec, quote_prec = fetch_precision(symbol)
            qty = calculate_quantity(invest_amount, price, base_prec)
            log_fn(f"Placing buy order for {qty} {symbol} at ₹{price:.2f}")
            place_order_with_retry("buy", symbol, qty, round(price, quote_prec), log_fn)
            manage_position(symbol, qty, price, log_fn)
        except Exception as e:
            log_fn(f"Error in trading loop: {e}")
        time.sleep(300)

# --- GUI ---
def start_bot():
    global bot_running
    invest = invest_amount.get()
    try:
        invest_val = float(invest)
        if invest_val <= 0:
            raise ValueError()
        bot_running = True
        btn_start.config(state=tk.DISABLED)
        btn_stop.config(state=tk.NORMAL)
        log(f"Starting bot with investment amount: ₹{invest_val:.2f}")
        threading.Thread(target=trading_bot_loop, args=(invest_val, log), daemon=True).start()
    except Exception:
        messagebox.showerror("Input Error", "Enter a valid positive investment amount.")

def stop_bot():
    global bot_running
    bot_running = False
    btn_start.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    log("Bot stopped by user.")

def log(msg):
    log_box.config(state=tk.NORMAL)
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)
    log_box.config(state=tk.DISABLED)

root = tk.Tk()
root.title("CoinSwitch INR Spot Auto Trading Bot (Stable Price Fetch)")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="Investment Amount (₹):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
invest_amount = ttk.Entry(frame, width=20)
invest_amount.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
invest_amount.insert(0, "5000")

btn_start = ttk.Button(frame, text="Start Bot", command=start_bot)
btn_start.grid(row=1, column=0, sticky=tk.EW, padx=5, pady=5)

btn_stop = ttk.Button(frame, text="Stop Bot", command=stop_bot, state=tk.DISABLED)
btn_stop.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)

log_box = tk.Text(frame, height=15, state=tk.DISABLED)
log_box.grid(row=2, column=0, columnspan=2, sticky=tk.NSEW, padx=5, pady=5)

frame.columnconfigure(1, weight=1)
frame.rowconfigure(2, weight=1)

root.mainloop()
