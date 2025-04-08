import re
import os
import urllib.parse
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import webbrowser
from datetime import datetime
import sys
import json


class PhishingDetector:
    def __init__(self):
        # List of trusted domains
        self.trusted_domains = [
            "google.com", "gmail.com", "microsoft.com", "office365.com",
            "amazon.com", "paypal.com", "apple.com", "facebook.com",
            "instagram.com", "twitter.com", "linkedin.com", "youtube.com",
            "netflix.com", "dropbox.com", "github.com", "outlook.com",
            "yahoo.com", "pinterest.com", "snapchat.com", "wordpress.com",
            "ebay.com", "whatsapp.com", "telegram.org", "zoom.us",
            "live.com", "hotmail.com", "skype.com", "adobe.com"
        ]

        # Words indicating urgency
        self.urgent_words = [
            "urgent", "immediately", "action required", "act now", "limited time",
            "expire", "suspended", "verify", "restricted", "warning", "alert",
            "security issue", "unauthorized", "login attempt", "critical",
            "account blocked", "unusual activity", "suspicious", "review needed",
            # Hebrew urgent words
            "דחוף", "מיידי", "נדרשת פעולה", "פעל עכשיו", "זמן מוגבל",
            "יפוג תוקף", "מושהה", "אמת", "מוגבל", "אזהרה", "התראה",
            "בעיית אבטחה", "לא מורשה", "ניסיון כניסה", "קריטי",
            "חשבון חסום", "פעילות חריגה", "חשוד", "נדרשת בדיקה"
        ]

        # Regular expressions to identify email addresses and URLs
        self.email_pattern = r'[\w\.-]+@[\w\.-]+'
        self.url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+|(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
        self.ip_in_url_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        
        # Common phishing phrases
        self.phishing_phrases = [
            "confirm your account", "verify your details", "update your information",
            "unusual activity", "problem with your account", "click here to verify",
            "security alert", "account suspended", "confirm identity", "validate your account",
            # Hebrew phishing phrases
            "אמת את חשבונך", "אמת את פרטיך", "עדכן את המידע שלך",
            "פעילות חריגה", "בעיה בחשבונך", "לחץ כאן לאימות",
            "התראת אבטחה", "חשבונך הושעה", "אמת את זהותך", "אשר את חשבונך"
        ]
        
        # Financial phrases that could indicate phishing
        self.financial_phrases = [
            "bank account", "credit card", "payment", "transaction", "transfer",
            "deposit", "withdraw", "refund", "billing", "invoice",
            # Hebrew financial phrases
            "חשבון בנק", "כרטיס אשראי", "תשלום", "עסקה", "העברה",
            "הפקדה", "משיכה", "החזר", "חיוב", "חשבונית"
        ]

    def read_email(self, file_path):
        """Read email content from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return file.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def check_suspicious_links(self, email_content):
        """Check for suspicious links"""
        suspicious_links = []

        # Find URLs in the email
        urls = re.findall(self.url_pattern, email_content)

        for url in urls:
            # Check if there is an IP address in the link (high risk indicator)
            if re.match(self.ip_in_url_pattern, url):
                suspicious_links.append(f"Link containing IP address: {url}")
                continue

            try:
                # Add http:// if not present to make parsing work correctly
                if not url.startswith('http'):
                    if url.startswith('www.'):
                        url = 'http://' + url
                    else:
                        # Skip things that aren't actually URLs
                        continue
                        
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc
                
                # Skip empty domains
                if not domain:
                    continue
                    
                # Remove www. from the domain if it exists
                if domain.startswith('www.'):
                    domain = domain[4:]

                # Check for URL encoding tricks
                if '%' in url:
                    suspicious_links.append(f"Link with URL encoding (possible obfuscation): {url}")
                    continue

                # Check for misleading URLs (text != href)
                if "href" in email_content.lower() and url in email_content:
                    href_pattern = f'href=["\']([^"\']*)["\'][^>]*>{url}'
                    matches = re.search(href_pattern, email_content)
                    if matches and matches.group(1) != url:
                        suspicious_links.append(f"Misleading link: Displays as {url} but links to {matches.group(1)}")
                
                # Check if the domain is not in the list of trusted domains
                trusted = False
                for trusted_domain in self.trusted_domains:
                    if domain.endswith(trusted_domain):
                        trusted = True
                        break

                if not trusted and domain:
                    suspicious_links.append(f"Link to unknown domain: {url} (domain: {domain})")
                    
                # Check for URL shorteners
                shortener_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc']
                if any(shortener in domain for shortener in shortener_services):
                    suspicious_links.append(f"Link using URL shortener (hides destination): {url}")
                
            except Exception as e:
                suspicious_links.append(f"Link with invalid format: {url} ({str(e)})")

        return suspicious_links

    def check_spoofed_addresses(self, email_content):
        """Check for spoofed sender addresses"""
        spoofed_addresses = []
        email_addresses = re.findall(self.email_pattern, email_content)

        for email in email_addresses:
            try:
                # Skip invalid emails
                if '@' not in email:
                    continue
                    
                domain = email.split('@')[1]

                # Look for domains similar to trusted domains but different
                for trusted_domain in self.trusted_domains:
                    if domain != trusted_domain and self.is_similar_domain(domain, trusted_domain):
                        spoofed_addresses.append(f"Suspicious email address: {email} (similar to {trusted_domain})")
            except Exception:
                continue

        return spoofed_addresses

    def is_similar_domain(self, domain1, domain2):
        """Check if two domains are similar but not identical"""
        # Simple similarity check - replacing one letter, adding or removing a letter
        if domain1 == domain2:
            return False

        # Simple method for checking similarity - reduced Levenshtein distance
        if domain2 in self.trusted_domains and domain1 != domain2:
            # Check for letter substitutions (for example gooogle instead of google)
            if domain2.replace('.', '') in domain1.replace('.', '') and domain1 != domain2:
                return True

            # Check for small changes in name (e.g., g00gle, googie)
            if len(domain1) == len(domain2):
                diff_count = 0
                for c1, c2 in zip(domain1, domain2):
                    if c1 != c2:
                        diff_count += 1
                if diff_count <= 2: 
                    return True

            # Check for adding/removing one character
            if abs(len(domain1) - len(domain2)) == 1:
                shorter = domain1 if len(domain1) < len(domain2) else domain2
                longer = domain2 if len(domain1) < len(domain2) else domain1

                for i in range(len(longer)):
                    test_str = longer[:i] + longer[i + 1:]
                    if test_str == shorter:
                        return True
                        
            # Check for domain typosquatting (e.g., goggle.com instead of google.com)
            if self.levenshtein_distance(domain1, domain2) <= 2:
                return True

        return False
        
    def levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def check_urgent_language(self, email_content):
        """Check for use of urgent language"""
        urgent_phrases = []
        lower_content = email_content.lower()

        for word in self.urgent_words:
            if word.lower() in lower_content:
                word_index = lower_content.find(word.lower())
                start = max(0, word_index - 20)
                end = min(len(email_content), word_index + len(word) + 20)
                context = email_content[start:end].replace('\n', ' ').strip()
                
                if start > 0:
                    context = "..." + context
                if end < len(email_content):
                    context = context + "..."
                
                urgent_phrases.append(f"Expression indicating urgency: '{word}' in context: \"{context}\"")

        return urgent_phrases
        
    def check_phishing_phrases(self, email_content):
        """Check for common phishing phrases"""
        detected_phrases = []
        lower_content = email_content.lower()
        
        for phrase in self.phishing_phrases:
            if phrase.lower() in lower_content:
                detected_phrases.append(f"Potential phishing phrase: '{phrase}'")
                
        return detected_phrases
        
    def check_financial_content(self, email_content):
        """Check for financial-related content which is common in phishing"""
        detected_phrases = []
        lower_content = email_content.lower()
        
        for phrase in self.financial_phrases:
            if phrase.lower() in lower_content:
                detected_phrases.append(f"Financial-related content: '{phrase}'")
                
        # Check for currency symbols as well
        currency_symbols = ['$', '€', '£', '¥', '₪']
        for symbol in currency_symbols:
            if symbol in email_content:
                detected_phrases.append(f"Contains currency symbol: '{symbol}'")
                break
                
        return detected_phrases
        
    def check_for_attachments(self, email_content):
        """Check for mentions of attachments, which could be malicious"""
        attachment_indicators = []
        
        attachment_terms = ['attachment', 'attached', 'file', 'document', 'קובץ', 'מצורף', 'מסמך']
        extension_terms = ['.exe', '.zip', '.rar', '.js', '.vbs', '.bat', '.scr', '.pif', '.doc', '.docx', '.xlsx', '.pdf']
        
        lower_content = email_content.lower()
        
        # Look for attachment terms
        for term in attachment_terms:
            if term.lower() in lower_content:
                attachment_indicators.append(f"References to attachments: '{term}'")
                break
                
        # Look for file extensions
        for ext in extension_terms:
            if ext.lower() in lower_content:
                attachment_indicators.append(f"Mentions file with extension: '{ext}'")
                
        return attachment_indicators

    def analyze_email_content(self, email_content):
        """Analyze email content directly"""
        if not email_content:
            return {"error": "No email content provided"}

        # Perform all checks
        suspicious_links = self.check_suspicious_links(email_content)
        spoofed_addresses = self.check_spoofed_addresses(email_content)
        urgent_phrases = self.check_urgent_language(email_content)
        phishing_phrases = self.check_phishing_phrases(email_content)
        financial_content = self.check_financial_content(email_content)
        attachment_indicators = self.check_for_attachments(email_content)

        # Calculate risk score based on weighted indicators
        risk_score = (
            len(suspicious_links) * 2 + 
            len(spoofed_addresses) * 3 + 
            len(urgent_phrases) * 1 +
            len(phishing_phrases) * 2 +
            len(financial_content) * 1 +
            len(attachment_indicators) * 1.5
        )

        # Set level based on score
        risk_level = "low"
        if risk_score >= 15:
            risk_level = "high"
        elif risk_score >= 5:
            risk_level = "medium"

        likely_phishing = risk_level != "low"

        # Create results report
        results = {
            "is_likely_phishing": likely_phishing,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "suspicious_links": suspicious_links,
            "spoofed_addresses": spoofed_addresses,
            "urgent_phrases": urgent_phrases,
            "phishing_phrases": phishing_phrases,
            "financial_content": financial_content,
            "attachment_indicators": attachment_indicators,
            "indicators_count": (
                len(suspicious_links) + 
                len(spoofed_addresses) + 
                len(urgent_phrases) +
                len(phishing_phrases) +
                len(financial_content) +
                len(attachment_indicators)
            ),
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        return results
        
    def save_results_to_file(self, results, output_path):
        """Save analysis results to a file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving results: {e}")
            return False



try:
    from ttkthemes import ThemedTk, ThemedStyle
    THEMED_AVAILABLE = True
except ImportError:
    THEMED_AVAILABLE = False
    print("For a better UI experience, install ttkthemes: pip install ttkthemes")


class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Phishing Detector")
        self.root.geometry("950x700")
        self.root.minsize(800, 650)

        self.detector = PhishingDetector()
        
        self.current_results = None
        
        self.dark_blue = "#1a2734"  
        self.white = "#FFFFFF" 
        self.highlight_blue = "#2c3e50"  

        if THEMED_AVAILABLE and isinstance(self.root, ThemedTk):
            try:
                self.root.set_theme("equilux") 
                style = ThemedStyle(self.root)
                style.configure("TLabel", foreground=self.white)
                style.configure("TButton", font=("Segoe UI", 10))
                style.configure("TLabelframe", foreground=self.white)
                style.configure("TLabelframe.Label", foreground=self.white)
            except Exception as e:
                print(f"Theme setting error: {e}")

            self.text_bg = self.dark_blue
            self.text_fg = self.white
            self.highlight_bg = self.highlight_blue
        else:
            self.text_bg = self.dark_blue
            self.text_fg = self.white
            self.highlight_bg = self.highlight_blue

        try:
            if getattr(sys, 'frozen', False):
                icon_path = os.path.join(sys._MEIPASS, "PDicon.ico")
            else:
                icon_path = "PDicon.ico"
                
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception as e:
            print(f"Could not load icon: {e}")

        self.main_frame = ttk.Frame(root, padding="15")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.root.configure(bg=self.dark_blue)
        if THEMED_AVAILABLE:
            self.main_frame.configure(style="TFrame")

        # Create UI elements
        self.create_ui_elements()

    def create_ui_elements(self):
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 15))

        logo_label = ttk.Label(title_frame, text="🛡️", font=("Arial", 28))
        logo_label.pack(side=tk.LEFT, padx=(0, 5))

        title_label = ttk.Label(title_frame, text="Email Phishing Detector", font=("Segoe UI", 22, "bold"))
        title_label.pack(side=tk.LEFT)

        subtitle_label = ttk.Label(self.main_frame,
                                   text="Analyze emails for potential phishing threats",
                                   font=("Segoe UI", 11))
        subtitle_label.pack(fill=tk.X, pady=(0, 15))

        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.VERTICAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Frame for input section
        input_frame = ttk.LabelFrame(self.paned_window, text="Email Content", padding=(10, 5))
        self.paned_window.add(input_frame, weight=1)

        self.email_text = scrolledtext.ScrolledText(
            input_frame,
            wrap=tk.WORD,
            height=8,
            font=("Consolas", 10),
            bg=self.text_bg,
            fg=self.text_fg,
            insertbackground=self.text_fg 
        )
        self.email_text.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)

        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 15))

        button_padding = (15, 8)

        load_button = ttk.Button(
            button_frame,
            text=" 📂 Load Email from File",
            command=self.load_email,
            padding=button_padding
        )
        load_button.pack(side=tk.LEFT, padx=5)

        analyze_button = ttk.Button(
            button_frame,
            text=" 🔍 Analyze Email",
            command=self.analyze_email,
            padding=button_padding
        )
        analyze_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(
            button_frame,
            text=" 💾 Save Results",
            command=self.save_results,
            padding=button_padding,
            state=tk.DISABLED  
        )
        self.save_button.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(
            button_frame,
            text=" 🗑️ Clear",
            command=self.clear_all,
            padding=button_padding
        )
        clear_button.pack(side=tk.LEFT, padx=5)
        
        about_button = ttk.Button(
            button_frame,
            text=" ℹ️ About",
            command=self.show_about,
            padding=button_padding
        )
        about_button.pack(side=tk.RIGHT, padx=5)

        # Results frame
        results_frame = ttk.LabelFrame(self.paned_window, text="Analysis Results", padding=(10, 5))
        self.paned_window.add(results_frame, weight=1)

        self.results_text = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            height=12,
            font=("Consolas", 10),
            bg=self.text_bg,
            fg=self.text_fg,
            state=tk.DISABLED
        )
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        status_frame = ttk.Frame(self.main_frame, relief=tk.SUNKEN)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            anchor=tk.W,
            padding=(10, 5)
        )
        status_bar.pack(fill=tk.X, side=tk.LEFT)

        version_label = ttk.Label(
            status_frame,
            text="v1.1.0",
            anchor=tk.E,
            padding=(10, 5)
        )
        version_label.pack(side=tk.RIGHT)
        
        self.root.update()
        self.paned_window.sashpos(0, int(self.paned_window.winfo_height()/2))

    def load_email(self):
        """Load email content from a file"""
        file_path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Text files", "*.txt"), ("Email files", "*.eml"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    email_content = file.read()
                    self.email_text.delete(1.0, tk.END)
                    self.email_text.insert(tk.END, email_content)
                self.status_var.set(f"Loaded email from: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
                self.status_var.set("Error loading file")

    def analyze_email(self):
        """Analyze the email content for phishing indicators"""
        email_content = self.email_text.get(1.0, tk.END).strip()

        if not email_content:
            messagebox.showwarning("Warning", "Please enter or load email content first")
            return

        self.status_var.set("Analyzing email...")
        self.root.update_idletasks()

        # Analyze email
        self.current_results = self.detector.analyze_email_content(email_content)

        # Display results
        self.display_results(self.current_results)
        
        self.save_button.config(state=tk.NORMAL)

        # Update status
        self.status_var.set(f"Analysis completed at {self.current_results['analysis_time']}")
        
    def save_results(self):
        """Save the current analysis results to a file"""
        if not self.current_results:
            messagebox.showinfo("Info", "No results to save. Please analyze an email first.")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Analysis Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            success = self.detector.save_results_to_file(self.current_results, file_path)
            if success:
                self.status_var.set(f"Results saved to: {file_path}")
                messagebox.showinfo("Success", f"Analysis results successfully saved to:\n{file_path}")
            else:
                self.status_var.set("Error saving results")
                messagebox.showerror("Error", "Failed to save results. Please try again.")

    def display_results(self, results):
        """Display the analysis results in the results area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)

        if "error" in results:
            self.results_text.insert(tk.END, f"Error: {results['error']}\n")
            self.results_text.config(state=tk.DISABLED)
            return

        warning_color = "#FF5555"  
        safe_color = "#55FF55"  

        # Risk level colors
        risk_high_color = "#FF5555"  # Red
        risk_medium_color = "#FFAA55"  # Orange
        risk_low_color = "#55FF55"  # Green

        self.results_text.tag_configure("warning", foreground=warning_color)
        self.results_text.tag_configure("safe", foreground=safe_color)
        self.results_text.tag_configure("risk_high", foreground=risk_high_color)
        self.results_text.tag_configure("risk_medium", foreground=risk_medium_color)
        self.results_text.tag_configure("risk_low", foreground=risk_low_color)
        self.results_text.tag_configure("heading", background=self.highlight_bg)

        if results["is_likely_phishing"]:
            self.results_text.insert(tk.END, "⚠️  WARNING: This email is suspected to be a phishing attempt!\n\n",
                                     "warning")
        else:
            self.results_text.insert(tk.END, "✅ The email appears to be legitimate.\n\n", "safe")

        suspicious_links_weight = 2
        spoofed_addresses_weight = 3
        urgent_phrases_weight = 1
        phishing_phrases_weight = 2
        financial_content_weight = 1
        attachment_indicators_weight = 1.5

        max_score_reference = 40  
        risk_level = results["risk_level"].upper()
        self.results_text.insert(tk.END, f"Risk level: {risk_level}", f"risk_{risk_level.lower()}")
        self.results_text.insert(tk.END, f" (Score: {results['risk_score']:.1f} out of {max_score_reference} reference)\n")

        self.results_text.insert(tk.END, f"Number of indicators found: {results['indicators_count']}\n\n")

        self.results_text.insert(tk.END, "--- SCORING EXPLANATION ---\n", "heading")
        self.results_text.insert(tk.END,
            f"• Suspicious links: {len(results['suspicious_links'])} found (× {suspicious_links_weight} points each = {len(results['suspicious_links']) * suspicious_links_weight} points)\n")
        self.results_text.insert(tk.END,
            f"• Spoofed addresses: {len(results['spoofed_addresses'])} found (× {spoofed_addresses_weight} points each = {len(results['spoofed_addresses']) * spoofed_addresses_weight} points)\n")
        self.results_text.insert(tk.END,
            f"• Urgent phrases: {len(results['urgent_phrases'])} found (× {urgent_phrases_weight} point each = {len(results['urgent_phrases']) * urgent_phrases_weight} points)\n")
        self.results_text.insert(tk.END,
 f"• Phishing phrases: {len(results['phishing_phrases'])} found (× {phishing_phrases_weight} points each = {len(results['phishing_phrases']) * phishing_phrases_weight} points)\n")
        self.results_text.insert(tk.END,
            f"• Financial content: {len(results['financial_content'])} found (× {financial_content_weight} point each = {len(results['financial_content']) * financial_content_weight} points)\n")
        self.results_text.insert(tk.END,
            f"• Attachment indicators: {len(results['attachment_indicators'])} found (× {attachment_indicators_weight} points each = {len(results['attachment_indicators']) * attachment_indicators_weight:.1f} points)\n")
        self.results_text.insert(tk.END, f"• Total score: {results['risk_score']:.1f} points\n\n")

        self.results_text.insert(tk.END, "Risk levels are determined as follows:\n")
        self.results_text.insert(tk.END, "• 0-4.9 points: LOW risk\n", "risk_low")
        self.results_text.insert(tk.END, "• 5-14.9 points: MEDIUM risk\n", "risk_medium")
        self.results_text.insert(tk.END, "• 15+ points: HIGH risk\n\n", "risk_high")

        if results["suspicious_links"]:
            heading = "--- SUSPICIOUS LINKS ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for link in results["suspicious_links"]:
                self.results_text.insert(tk.END, f"• {link}\n")
            self.results_text.insert(tk.END, "\n")

        if results["spoofed_addresses"]:
            heading = "--- SUSPICIOUS EMAIL ADDRESSES ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for address in results["spoofed_addresses"]:
                self.results_text.insert(tk.END, f"• {address}\n")
            self.results_text.insert(tk.END, "\n")

        if results["urgent_phrases"]:
            heading = "--- EXPRESSIONS INDICATING URGENCY ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for phrase in results["urgent_phrases"]:
                self.results_text.insert(tk.END, f"• {phrase}\n")
            self.results_text.insert(tk.END, "\n")
            
        if results["phishing_phrases"]:
            heading = "--- PHISHING PHRASES DETECTED ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for phrase in results["phishing_phrases"]:
                self.results_text.insert(tk.END, f"• {phrase}\n")
            self.results_text.insert(tk.END, "\n")
            
        if results["financial_content"]:
            heading = "--- FINANCIAL REFERENCES ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for item in results["financial_content"]:
                self.results_text.insert(tk.END, f"• {item}\n")
            self.results_text.insert(tk.END, "\n")
            
        if results["attachment_indicators"]:
            heading = "--- ATTACHMENT REFERENCES ---\n"
            self.results_text.insert(tk.END, heading, "heading")

            for item in results["attachment_indicators"]:
                self.results_text.insert(tk.END, f"• {item}\n")
            self.results_text.insert(tk.END, "\n")

        self.results_text.config(state=tk.DISABLED)

    def clear_all(self):
        """Clear all input and results"""
        self.email_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.current_results = None
        self.save_button.config(state=tk.DISABLED)
        self.status_var.set("Ready")
        
    def show_about(self):
        """Show information about the application"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About Email Phishing Detector")
        about_window.geometry("500x400")
        about_window.resizable(False, False)
        about_window.configure(bg=self.dark_blue)
        
        # Make the window modal
        about_window.transient(self.root)
        about_window.grab_set()
        
        about_window.update_idletasks()
        width = about_window.winfo_width()
        height = about_window.winfo_height()
        x = (about_window.winfo_screenwidth() // 2) - (width // 2)
        y = (about_window.winfo_screenheight() // 2) - (height // 2)
        about_window.geometry(f"{width}x{height}+{x}+{y}")
        
        content_frame = ttk.Frame(about_window, padding=20)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        logo_label = ttk.Label(content_frame, text="🛡️", font=("Arial", 40))
        logo_label.pack(pady=(10, 5))
        
        title_label = ttk.Label(
            content_frame, 
            text="Email Phishing Detector", 
            font=("Segoe UI", 18, "bold")
        )
        title_label.pack(pady=(0, 10))
        
        version_label = ttk.Label(
            content_frame,
            text="Version 1.1.0",
            font=("Segoe UI", 10)
        )
        version_label.pack()
        
        description = (
            "This tool analyzes email content to identify potential phishing attempts "
            "by examining links, email addresses, and language patterns commonly "
            "associated with phishing attacks."
        )
        
        desc_label = ttk.Label(
            content_frame,
            text=description,
            wraplength=450,
            justify=tk.CENTER,
            padding=(0, 20)
        )
        desc_label.pack(fill=tk.X)
        
        separator = ttk.Separator(content_frame, orient="horizontal")
        separator.pack(fill=tk.X, pady=10)
        
        credit_label = ttk.Label(
            content_frame,
            text="Developed by Tomer Amitai.",
            font=("Segoe UI", 9),
            justify=tk.CENTER
        )
        credit_label.pack(pady=5)
        
        year_label = ttk.Label(
            content_frame,
            text=f"© {datetime.now().year}",
            font=("Segoe UI", 9),
            justify=tk.CENTER
        )
        year_label.pack()
        
        close_button = ttk.Button(
            content_frame,
            text="Close",
            command=about_window.destroy,
            padding=(20, 8)
        )
        close_button.pack(pady=15)


def main():
    if THEMED_AVAILABLE:
        try:
            root = ThemedTk(theme="equilux")
        except Exception as e:
            print(f"Could not initialize ThemedTk: {e}")
            root = tk.Tk()
            root.configure(bg="#1a2734")
    else:
        root = tk.Tk()
        root.configure(bg="#1a2734")

    app = PhishingDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()