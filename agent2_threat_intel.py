"""
Agent 2 - Threat Intel Agent (Zero-Day Scraper)
Scrapes zero-day intelligence from multiple sources, creates vector embeddings,
and stores in Qdrant for pattern matching.
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import time
import re
import asyncio
from typing import List, Dict, Any
import json
import logging
from datetime import datetime
import hashlib
import schedule
import os
import sys
import subprocess
import requests

from qdrant_client import QdrantClient
from qdrant_client.http.models import PointStruct, VectorParams, Distance

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Ollama embedding model name (default: nomic-embed-text:latest)
OLLAMA_EMBED_MODEL = os.getenv('OLLAMA_EMBED_MODEL', 'nomic-embed-text:latest')
OLLAMA_GEN_MODEL = os.getenv('OLLAMA_GEN_MODEL', 'llama3.1:latest')
OLLAMA_API_URL = os.getenv('OLLAMA_API_URL', 'http://localhost:11434')


class ThreatIntelAgent:
    """Scrapes and vectorizes zero-day threat intelligence into Qdrant."""

    def __init__(self, collection_name: str = "zero-day-intel", qdrant_url: str = None):
        self.collection_name = collection_name
        self.embedding_model_name = OLLAMA_EMBED_MODEL
        self.generation_model_name = OLLAMA_GEN_MODEL
        self.ollama_api_url = OLLAMA_API_URL
        qdrant_url = qdrant_url or os.getenv("QDRANT_URL", "http://localhost:6333")
        self.qdrant = QdrantClient(url=qdrant_url)

        # Determine embedding dim by testing Ollama embedding API
        # nomic-embed-text produces 768-dimensional embeddings
        try:
            test_embedding = self.create_embedding("test")
            self.embedding_dim = len(test_embedding)
            logger.info(f"Using Ollama embedding model '{self.embedding_model_name}' with dimension {self.embedding_dim}")
        except Exception as e:
            logger.warning(f"Could not determine embedding dimension from Ollama: {e}. Using default 768 for nomic-embed-text.")
            self.embedding_dim = 768  # nomic-embed-text default dimension

        # Ensure collection exists with correct vector params
        try:
            existing_collection = self.qdrant.get_collection(collection_name=self.collection_name)
            # Check if the collection has the correct vector dimension
            existing_dim = None
            
            # Try to get dimension from collection config
            try:
                if hasattr(existing_collection, 'config') and hasattr(existing_collection.config, 'params'):
                    params = existing_collection.config.params
                    if hasattr(params, 'vectors'):
                        vectors_config = params.vectors
                        # Handle different vector config types
                        if hasattr(vectors_config, 'size'):
                            existing_dim = vectors_config.size
                        elif isinstance(vectors_config, dict):
                            existing_dim = vectors_config.get('size')
                        elif hasattr(vectors_config, 'get'):
                            existing_dim = vectors_config.get('size')
            except Exception as e:
                logger.debug(f"Could not get dimension from config: {e}")
            
            # If dimension not found in config, try to get from a sample point
            if existing_dim is None:
                try:
                    scroll_result = self.qdrant.scroll(
                        collection_name=self.collection_name,
                        limit=1,
                        with_vectors=True
                    )
                    if scroll_result and len(scroll_result) >= 2 and scroll_result[0]:
                        points = scroll_result[0]
                        if points and len(points) > 0:
                            point = points[0]
                            if hasattr(point, 'vector'):
                                vector = point.vector
                                if isinstance(vector, list):
                                    existing_dim = len(vector)
                                elif hasattr(vector, '__len__'):
                                    existing_dim = len(vector)
                except Exception as e:
                    logger.debug(f"Could not get dimension from sample point: {e}")
            
            # Check if we need to recreate the collection
            if existing_dim is not None and existing_dim != self.embedding_dim:
                logger.warning(
                    f"Collection '{self.collection_name}' has dimension {existing_dim}, "
                    f"but current embedding model requires {self.embedding_dim}. "
                    f"Recreating collection with correct dimension (this will delete existing data)..."
                )
                # Recreate collection with correct dimension
                if self.qdrant.collection_exists(self.collection_name):
                    self.qdrant.delete_collection(self.collection_name)
                
                params = VectorParams(size=self.embedding_dim, distance=Distance.COSINE)
                self.qdrant.create_collection(collection_name=self.collection_name, vectors_config=params)
                logger.info(f"Recreated collection '{self.collection_name}' with dimension {self.embedding_dim}")
            else:
                if existing_dim is None:
                    logger.info(f"Collection '{self.collection_name}' already exists (could not determine dimension, assuming correct)")
                else:
                    logger.info(f"Collection '{self.collection_name}' already exists with correct dimension {existing_dim}")
        except Exception as e:
            # Collection doesn't exist, create it
            try:
                params = VectorParams(size=self.embedding_dim, distance=Distance.COSINE)
                self.qdrant.create_collection(collection_name=self.collection_name, vectors_config=params)
                logger.info(f"Created collection '{self.collection_name}' with dimension {self.embedding_dim}")
            except Exception as creation_error:
                # Handle race condition where another process created it first
                if "already exists" in str(creation_error) or "already exist" in str(creation_error).lower():
                    logger.info(f"Collection '{self.collection_name}' was created by another process")
                else:
                    raise

    def clean_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", text).strip()
    
    def normalize_payload(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize scraped threat intel data to Qdrant-compatible payload.
        """
        normalized = {}
        
        # Standard field mappings (source-specific to normalized)
        # Normalize source names to consistent, readable format
        source_raw = item.get('Source', item.get('source', 'Unknown'))
        source_map = {
            'SOCRadar': 'SOCRadar',
            'ISC SANS Diary': 'ISC SANS',
            'ZDI Blog': 'ZDI',
            'TheHackerNews Weekly Recap': 'HackerNews',
            'hackernews': 'HackerNews',
            'zdi': 'ZDI',
            'isc_sans': 'ISC SANS',
            'socradar': 'SOCRadar'
        }
        source = source_map.get(source_raw, source_raw)
        
        # Normalize title
        title = item.get('Title', item.get('title', ''))
        if title:
            normalized['title'] = str(title).strip()
        else:
            normalized['title'] = ''
        
        # Normalize source
        normalized['source'] = source
        
        # Normalize URL
        url = item.get('URL', item.get('url', item.get('Url', '')))
        normalized['url'] = str(url) if url else ''
        
        # Normalize timestamp/published date
        timestamp = item.get('Timestamp', item.get('timestamp', item.get('Published', item.get('published', ''))))
        if timestamp:
            if isinstance(timestamp, datetime):
                normalized['published'] = timestamp.isoformat()
            else:
                normalized['published'] = str(timestamp)
        else:
            normalized['published'] = datetime.now().isoformat()
        
        # Normalize summary/description/content
        summary = item.get('Summary', item.get('summary', item.get('Content', item.get('content', item.get('Description', item.get('description', ''))))))
        normalized['summary'] = str(summary).strip() if summary else ''
        
        # Normalize severity (ZDI specific, but make it available for all)
        severity = item.get('Severity', item.get('severity', item.get('CVSS', item.get('cvss', ''))))
        if severity:
            # Normalize severity values
            severity_str = str(severity).strip().upper()
            if severity_str in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                normalized['severity'] = severity_str
            elif 'CVSS' in severity_str or any(c.isdigit() for c in severity_str):
                # Extract CVSS score and map to severity
                try:
                    cvss_match = re.search(r'(\d+\.?\d*)', severity_str)
                    if cvss_match:
                        cvss_score = float(cvss_match.group(1))
                        if cvss_score >= 9.0:
                            normalized['severity'] = 'CRITICAL'
                        elif cvss_score >= 7.0:
                            normalized['severity'] = 'HIGH'
                        elif cvss_score >= 4.0:
                            normalized['severity'] = 'MEDIUM'
                        else:
                            normalized['severity'] = 'LOW'
                    else:
                        normalized['severity'] = severity_str
                except:
                    normalized['severity'] = severity_str
            else:
                normalized['severity'] = severity_str
        else:
            normalized['severity'] = 'UNKNOWN'
        
        # AI severity estimation if still UNKNOWN
        if normalized['severity'] == 'UNKNOWN' and (normalized.get('title') or normalized.get('summary')):
            normalized['severity'] = self.estimate_severity(normalized.get('title', ''), normalized.get('summary', ''))
        
        # Additional fields for ZDI
        if 'CVE' in item or 'cve' in item:
            cve = item.get('CVE', item.get('cve', ''))
            normalized['cve'] = str(cve).strip() if cve else ''
        
        if 'Type' in item or 'type' in item:
            threat_type = item.get('Type', item.get('type', ''))
            normalized['threat_type'] = str(threat_type).strip() if threat_type else ''
        
        if 'Public' in item or 'public' in item:
            public = item.get('Public', item.get('public', ''))
            normalized['public'] = str(public).strip() if public else ''
        
        if 'Exploited' in item or 'exploited' in item:
            exploited = item.get('Exploited', item.get('exploited', ''))
            normalized['exploited'] = str(exploited).strip() if exploited else ''
        
        # Category for HackerNews
        if 'Category' in item or 'category' in item:
            category = item.get('Category', item.get('category', ''))
            normalized['category'] = str(category).strip() if category else ''
        
        # Ensure all values are Qdrant-compatible (no None, no complex objects)
        for key, value in list(normalized.items()):
            if value is None:
                normalized[key] = ''
            elif isinstance(value, (dict, list)):
                normalized[key] = json.dumps(value, ensure_ascii=False)
            elif not isinstance(value, (str, int, float, bool)):
                normalized[key] = str(value)
            # Remove empty strings for optional fields (but keep required ones)
            elif value == '' and key in ['cve', 'threat_type', 'public', 'exploited', 'category']:
                # Remove optional empty fields to keep payload clean
                del normalized[key]
        
        # Validate required fields
        if not normalized.get('title') and not normalized.get('summary'):
            logger.warning(f"Skipping item with no title or summary: {normalized}")
            return None
        
        # Ensure indicators exist (from my previous logic, might be useful to add back simple extraction or keep clean)
        # The user's code removed the explicit 'indicators' extraction list.
        # I'll respect their code.
        
        return normalized

    def estimate_severity(self, title: str, summary: str) -> str:
        """Use Ollama to estimate severity if not explicitly provided."""
        text = f"Title: {title}\nSummary: {summary}\n"
        prompt = (
            "You are a threat intelligence analyst. Based on the provided news title and summary, "
            "determine the severity of the threat.\n"
            "Rules:\n"
            " - CRITICAL for zero-days, active exploitation, unauthenticated RCE.\n"
            " - HIGH for severe vulnerabilities, authentication bypass, data leaks.\n"
            " - MEDIUM for moderate info, CSRF, XSS, or ongoing non-critical threats.\n"
            " - LOW for minor bugs or best practices.\n"
            " - INFO for standard news, patch releases without active exploits.\n\n"
            "Respond ONLY with one of the following words: CRITICAL, HIGH, MEDIUM, LOW, or INFO.\n\n"
            f"{text}\nSeverity:"
        )

        try:
            api_url = f"{self.ollama_api_url}/api/generate"
            payload = {
                "model": self.generation_model_name,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 10
                }
            }
            response = requests.post(api_url, json=payload, timeout=20)
            response.raise_for_status()
            
            result = response.json().get("response", "").strip().upper()
            
            for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if s in result:
                    return s
            return 'UNKNOWN'
        except Exception as e:
            logger.warning(f"Ollama severity estimation failed: {e}")
            return 'UNKNOWN'
    

    def create_semantic_text(self, normalized_item: Dict[str, Any]) -> str:
        """
        Create semantic text for embedding from normalized threat intel.
        Focuses on searchable content rather than full JSON.
        """
        parts = []
        
        # Title is most important
        if normalized_item.get('title'):
            parts.append(normalized_item['title'])
        
        # Summary/description
        if normalized_item.get('summary'):
            parts.append(normalized_item['summary'])
        
        # Source and category
        source = normalized_item.get('source', '')
        category = normalized_item.get('category', '')
        if source:
            parts.append(f"Source: {source}")
        if category:
            parts.append(f"Category: {category}")
        
        # CVE and severity for ZDI
        cve = normalized_item.get('cve', '')
        severity = normalized_item.get('severity', '')
        if cve:
            parts.append(f"CVE: {cve}")
        if severity and severity != 'UNKNOWN':
            parts.append(f"Severity: {severity}")
        
        # Threat type
        threat_type = normalized_item.get('threat_type', '')
        if threat_type:
            parts.append(f"Type: {threat_type}")
        
        return ' '.join(parts)

    def create_embedding(self, text: str) -> List[float]:
        """Create embedding using Ollama's embedding API."""
        try:
            # Use Ollama HTTP API for embeddings
            api_url = f"{self.ollama_api_url}/api/embeddings"
            payload = {
                "model": self.embedding_model_name,
                "prompt": text
            }
            
            response = requests.post(api_url, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            embedding = result.get("embedding", [])
            
            if not embedding:
                raise ValueError("Empty embedding returned from Ollama")
            
            # Ensure it's a list of floats
            return [float(x) for x in embedding]
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Ollama API request failed: {e}. Trying subprocess fallback...")
            # Fallback to subprocess if HTTP API fails
            return self._create_embedding_subprocess(text)
        except Exception as e:
            logger.error(f"Error creating embedding: {e}. Using hash fallback.")
            # Final fallback: simple hash-based embedding
            return self._create_hash_embedding(text)
    
    def _create_embedding_subprocess(self, text: str) -> List[float]:
        """Fallback: Create embedding using Ollama CLI subprocess."""
        try:
            # Use ollama embeddings command
            proc = subprocess.run(
                ["ollama", "embeddings", self.embedding_model_name, text],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            
            if proc.returncode == 0:
                # Parse JSON output from ollama embeddings command
                result = json.loads(proc.stdout.strip())
                embedding = result.get("embedding", [])
                if embedding:
                    return [float(x) for x in embedding]
            
            raise ValueError(f"Ollama subprocess failed: {proc.stderr}")
            
        except Exception as e:
            logger.warning(f"Ollama subprocess embedding failed: {e}")
            return self._create_hash_embedding(text)
    
    def _create_hash_embedding(self, text: str) -> List[float]:
        """Final fallback: Create simple hash-based embedding."""
        h = hashlib.md5(text.encode()).hexdigest()
        # Create 768-dim embedding by repeating and scaling hash values
        hash_values = [float(int(h[i:i+2], 16)) / 255.0 for i in range(0, 32, 2)]
        # Repeat to reach 768 dimensions (nomic-embed-text size)
        while len(hash_values) < 768:
            hash_values.extend(hash_values[:min(16, 768 - len(hash_values))])
        return hash_values[:768]

    def fetch_attack_details_socradar(self, driver, url: str) -> List[Dict[str, Any]]:
        driver.get(url)
        time.sleep(3)
        attack_data = []
        articles = driver.find_elements(By.TAG_NAME, 'h5')

        for article in articles:
            try:
                link_element = article.find_element(By.TAG_NAME, 'a')
                title = self.clean_text(link_element.text)
                summary_element = driver.execute_script("return arguments[0].nextElementSibling", article)
                summary = self.clean_text(summary_element.text) if summary_element and summary_element.tag_name == 'p' else ""

                attack_data.append({
                    'Source': 'SOCRadar',
                    'Title': title,
                    'Summary': summary,
                    'URL': link_element.get_attribute('href'),
                    'Timestamp': datetime.now().isoformat()
                })
            except Exception:
                continue

        return attack_data

    def fetch_attack_details_isc(self, driver, url: str) -> List[Dict[str, Any]]:
        driver.get(url)
        time.sleep(3)
        attack_data = []
        diaries = driver.find_elements(By.CSS_SELECTOR, 'div.isc-card')

        for diary in diaries:
            try:
                title_elem = diary.find_element(By.CSS_SELECTOR, 'h2.card-title a')
                title = self.clean_text(title_elem.text)
                summary_elem = diary.find_element(By.CSS_SELECTOR, 'div.card-content[tabindex="0"]')
                summary = self.clean_text(summary_elem.text)

                attack_data.append({
                    'Source': 'ISC SANS Diary',
                    'Title': title,
                    'Summary': summary,
                    'URL': title_elem.get_attribute('href'),
                    'Timestamp': datetime.now().isoformat()
                })
            except Exception:
                continue

        return attack_data

    def fetch_first_zdi_blog_table(self, driver) -> List[Dict[str, Any]]:
        base_url = "https://www.zerodayinitiative.com"
        blog_main_url = base_url + "/blog/"
        driver.get(blog_main_url)
        time.sleep(3)

        try:
            first_blog = driver.find_element(By.CSS_SELECTOR, 'div[id^="post-"]')
            post_url_path = first_blog.find_element(By.CSS_SELECTOR, 'h2.title a').get_attribute('href')
            post_url = base_url + post_url_path if post_url_path.startswith('/') else post_url_path
            driver.get(post_url)
            time.sleep(3)

            rows = driver.find_elements(By.CSS_SELECTOR, 'table tr')
            zdi_data = []

            for row in rows[1:]:
                cols = row.find_elements(By.TAG_NAME, 'td')
                if len(cols) >= 7:
                    zdi_data.append({
                        'Source': 'ZDI Blog',
                        'CVE': self.clean_text(cols[0].text),
                        'Title': self.clean_text(cols[1].text),
                        'Severity': self.clean_text(cols[2].text),
                        'CVSS': self.clean_text(cols[3].text),
                        'Public': self.clean_text(cols[4].text),
                        'Exploited': self.clean_text(cols[5].text),
                        'Type': self.clean_text(cols[6].text),
                        'Timestamp': datetime.now().isoformat()
                    })

            return zdi_data
        except Exception as e:
            logger.error(f"Error fetching ZDI data: {e}")
            return []

    def fetch_hackernews_weekly_recap(self, driver) -> List[Dict[str, Any]]:
        base_url = "https://thehackernews.com"
        search_url = base_url + "/search/label/data%20breach"
        driver.get(search_url)
        time.sleep(3)

        titles = driver.find_elements(By.CSS_SELECTOR, 'h2.home-title')
        recap_title_elem = None

        for t in titles:
            if "Weekly Recap" in t.text:
                recap_title_elem = t
                break

        if not recap_title_elem:
            return []

        post_url = None
        try:
            post_url = recap_title_elem.find_element(By.TAG_NAME, 'a').get_attribute('href')
        except:
            try:
                post_url = recap_title_elem.find_element(By.XPATH, './ancestor::div//a').get_attribute('href')
            except:
                try:
                    post_url = recap_title_elem.find_element(By.XPATH, './following-sibling::a').get_attribute('href')
                except:
                    return []

        driver.get(post_url)
        time.sleep(3)

        extracted_entries = []

        try:
            p_elems = driver.find_elements(By.TAG_NAME, 'p')
            for p in p_elems:
                if 'Threat of the Week' in p.text:
                    extracted_entries.append({
                        'Source': 'TheHackerNews Weekly Recap',
                        'Category': 'Threat of the Week',
                        'Content': self.clean_text(p.text),
                        'Timestamp': datetime.now().isoformat()
                    })
                    break
        except:
            pass

        try:
            top_news_ul = driver.find_element(By.XPATH, '//*[@id="-top-news"]/following-sibling::ul[1]')
            for li in top_news_ul.find_elements(By.TAG_NAME, 'li'):
                extracted_entries.append({
                    'Source': 'TheHackerNews Weekly Recap',
                    'Category': 'Top News',
                    'Content': self.clean_text(li.text),
                    'Timestamp': datetime.now().isoformat()
                })
        except:
            pass

        try:
            for p in p_elems:
                if "This week's list includes" in p.text:
                    extracted_entries.append({
                        'Source': 'TheHackerNews Weekly Recap',
                        'Category': 'Trending CVE',
                        'Content': self.clean_text(p.text),
                        'Timestamp': datetime.now().isoformat()
                    })
                    break
        except:
            pass

        try:
            around_world_ul = driver.find_element(By.XPATH, '//*[@id="-around-the-cyber-world"]/following-sibling::ul[1]')
            for li in around_world_ul.find_elements(By.TAG_NAME, 'li'):
                extracted_entries.append({
                    'Source': 'TheHackerNews Weekly Recap',
                    'Category': 'Around the Cyber World',
                    'Content': self.clean_text(li.text),
                    'Timestamp': datetime.now().isoformat()
                })
        except:
            pass

        return extracted_entries

    def collect_all_sources(self) -> List[Dict[str, Any]]:
        """Collect threat intelligence from all sources."""
        logger.info("Starting web scraping for threat intelligence...")
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-software-rasterizer')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-logging')
        chrome_options.add_argument('--log-level=3')  # Suppress INFO, WARNING, ERROR logs
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument('--ignore-certificate-errors')  # Handle SSL issues
        chrome_options.add_argument('--ignore-ssl-errors')
        chrome_options.add_argument('--ignore-certificate-errors-spki-list')
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        chrome_options.add_argument(
            'user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )

        driver = None
        combined_data = []
        
        try:
            logger.info("Initializing Chrome WebDriver...")
            driver = webdriver.Chrome(options=chrome_options)
            logger.info("Chrome WebDriver initialized successfully")
            
            socradar_url = "https://socradar.io/category/cyber-news/"
            isc_url = "https://isc.sans.edu/diaryarchive.html"

            # Collect from each source with error handling
            logger.info("Scraping SOCRadar...")
            try:
                data_socradar = self.fetch_attack_details_socradar(driver, socradar_url)
                logger.info(f"Collected {len(data_socradar)} items from SOCRadar")
                combined_data.extend(data_socradar)
            except Exception as e:
                error_msg = str(e)
                if "SSL" in error_msg or "certificate" in error_msg.lower() or "handshake" in error_msg.lower():
                    logger.warning(f"SSL/Certificate error scraping SOCRadar (non-fatal): {e}")
                else:
                    logger.error(f"Error scraping SOCRadar: {e}", exc_info=True)

            logger.info("Scraping ISC SANS...")
            try:
                data_isc = self.fetch_attack_details_isc(driver, isc_url)
                logger.info(f"Collected {len(data_isc)} items from ISC SANS")
                combined_data.extend(data_isc)
            except Exception as e:
                error_msg = str(e)
                if "SSL" in error_msg or "certificate" in error_msg.lower() or "handshake" in error_msg.lower():
                    logger.warning(f"SSL/Certificate error scraping ISC SANS (non-fatal): {e}")
                else:
                    logger.error(f"Error scraping ISC SANS: {e}", exc_info=True)

            logger.info("Scraping ZDI Blog...")
            try:
                data_zdi = self.fetch_first_zdi_blog_table(driver)
                logger.info(f"Collected {len(data_zdi)} items from ZDI Blog")
                combined_data.extend(data_zdi)
            except Exception as e:
                logger.error(f"Error scraping ZDI Blog: {e}", exc_info=True)

            logger.info("Scraping HackerNews Weekly Recap...")
            try:
                data_hackernews = self.fetch_hackernews_weekly_recap(driver)
                logger.info(f"Collected {len(data_hackernews)} items from HackerNews")
                combined_data.extend(data_hackernews)
            except Exception as e:
                logger.error(f"Error scraping HackerNews: {e}", exc_info=True)

            logger.info(f"Total collected: {len(combined_data)} threat intelligence items")
            return combined_data
            
        except Exception as e:
            logger.error(f"Critical error in collect_all_sources: {e}", exc_info=True)
            return combined_data
        finally:
            if driver:
                try:
                    driver.quit()
                    logger.info("Chrome WebDriver closed")
                except Exception as e:
                    logger.warning(f"Error closing WebDriver: {e}")

    def vectorize_and_store(self, threat_data: List[Dict[str, Any]]) -> int:
        """Store threat intel with normalized payloads and proper ID generation."""
        stored_count = 0
        seen_ids = set()  # Track IDs to avoid collisions

        for item in threat_data:
            try:
                # Step 1: Normalize payload to Qdrant-compatible format
                normalized_payload = self.normalize_payload(item)
                
                # Skip if normalization failed
                if normalized_payload is None:
                    continue
                
                # Step 2: Create semantic text for embedding (not full JSON)
                semantic_text = self.create_semantic_text(normalized_payload)
                
                if not semantic_text.strip():
                    logger.warning(f"Skipping item with empty semantic text: {normalized_payload.get('title', 'N/A')}")
                    continue
                
                # Step 3: Create embedding from semantic text
                embedding = self.create_embedding(semantic_text)
                if not embedding or len(embedding) != self.embedding_dim:
                    logger.warning(f"Invalid embedding for item: {normalized_payload.get('title', 'N/A')}")
                    continue
                
                # Step 4: Generate unique ID (avoid collisions)
                # Use combination of source, title, url, and timestamp for uniqueness
                id_string = f"{normalized_payload.get('source', '')}:{normalized_payload.get('title', '')}:{normalized_payload.get('url', '')}:{normalized_payload.get('published', '')}"
                id_hash = hashlib.sha256(id_string.encode('utf-8')).hexdigest()
                
                # Convert to integer ID (use first 15 hex chars to avoid overflow)
                pid = int(id_hash[:15], 16)
                
                # Handle collisions by appending counter
                original_pid = pid
                collision_count = 0
                while pid in seen_ids:
                    collision_count += 1
                    # Append collision counter to hash
                    pid = int(id_hash[:14] + str(collision_count), 16) if collision_count < 10 else int(id_hash[:13] + str(collision_count), 16)
                    if collision_count > 100:
                        logger.error(f"Too many ID collisions for item: {normalized_payload.get('title', 'N/A')}")
                        break
                
                seen_ids.add(pid)
                
                # Step 5: Store in Qdrant with normalized payload
                pts = [PointStruct(id=pid, vector=list(embedding), payload=normalized_payload)]
                self.qdrant.upsert(collection_name=self.collection_name, points=pts)

                stored_count += 1
                if stored_count % 10 == 0:
                    logger.info(f"Stored {stored_count} threat intel items...")
                logger.debug(f"Stored: {normalized_payload.get('source', 'Unknown')} - {normalized_payload.get('title', 'N/A')[:50]}")

            except Exception as e:
                logger.error(f"Error storing threat intel: {e}", exc_info=True)

        logger.info(f"Successfully stored {stored_count} threat intelligence items in Qdrant")
        return stored_count

    def search_similar_threats(self, query_text: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for similar threats using vector similarity search."""
        try:
            # Verify collection exists
            try:
                collection_info = self.qdrant.get_collection(self.collection_name)
                # Check if collection has any points
                if collection_info.points_count == 0:
                    logger.warning(f"Collection '{self.collection_name}' is empty. No threat intel data available.")
                    return []
            except Exception as e:
                logger.error(f"Collection '{self.collection_name}' not accessible: {e}")
                return []
            
            # Create query embedding
            query_embedding = self.create_embedding(query_text)
            if not query_embedding or len(query_embedding) != self.embedding_dim:
                logger.error(f"Embedding dimension mismatch: expected {self.embedding_dim}, got {len(query_embedding) if query_embedding else 0}")
                return []
            
            # Ensure embedding is a list of floats
            query_vector = list(map(float, query_embedding))
            
            # Perform vector search (qdrant-client API varies by version)
            try:
                if hasattr(self.qdrant, "query_points"):
                    # Newer qdrant-client
                    result = self.qdrant.query_points(
                        collection_name=self.collection_name,
                        query=query_vector,
                        limit=n_results,
                        with_payload=True,
                        with_vectors=False,
                    )
                    # Extract points from QueryResponse
                    if hasattr(result, "points"):
                        hits = result.points
                    elif isinstance(result, list):
                        hits = result
                    else:
                        logger.warning(f"Unexpected result type from query_points: {type(result)}")
                        hits = []
                else:
                    # Older qdrant-client
                    hits = self.qdrant.search(
                        collection_name=self.collection_name,
                        query_vector=query_vector,
                        limit=n_results,
                        with_payload=True,
                        with_vectors=False,
                    )
                    
            except Exception as search_error:
                logger.error(f"Vector search failed: {search_error}", exc_info=True)
                return []

            similar_threats = []
            for h in hits:
                # Handle different response formats
                if hasattr(h, 'payload'):
                    payload = h.payload
                    point_id = h.id
                    score = getattr(h, 'score', 0.0)
                elif isinstance(h, dict):
                    payload = h.get('payload', {})
                    point_id = h.get('id')
                    score = h.get('score', 0.0)
                else:
                    logger.warning(f"Unexpected hit format: {type(h)}")
                    continue
                
                similar_threats.append({
                    'threat_data': payload or {},
                    'id': point_id,
                    'score': float(score) if score else 0.0
                })

            logger.debug(f"Found {len(similar_threats)} similar threats for query: {query_text[:50]}...")
            return similar_threats
            
        except Exception as e:
            logger.error(f"Error searching threats: {e}", exc_info=True)
            return []

    def run_collection(self):
        logger.info("Starting threat intelligence collection...")
        try:
            threat_data = self.collect_all_sources()
            stored_count = self.vectorize_and_store(threat_data)
            logger.info(f"Collected and stored {stored_count} threat intelligence items")
            return threat_data
        except Exception as e:
            logger.error(f"Error in threat collection: {e}")
            return []


async def zero_day_feeds() -> dict:
    """Async helper to fetch zero-day feeds without MCP.

    Returns a dict similar to the previous MCP tool output.
    """
    agent = ThreatIntelAgent()
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, agent.collect_all_sources)
    return {"results": data}


if __name__ == "__main__":
    # --- Modified Main Block for Pipeline Execution ---
    # The original code provided was designed as a long-running service with schedule.
    # To maintain compatibility with 'run_pipeline.ps1', this block:
    # 1. Runs the collection once.
    # 2. Triggers the next agent (Agent 3).
    # 3. Exits (does not loop forever).
    
    agent = ThreatIntelAgent()
    
    # 1. Run collection immediately
    agent.run_collection()
    
    # 2. Trigger Agent 3 (Pipeline continuation)
    logger.info("Triggering Agent 3 (Synthetic Pattern Generator)...")
    try:
        cmd = [sys.executable, "agent3_synthetic_gen.py"]
        subprocess.Popen(cmd)
        logger.info("Agent 3 triggered successfully.")
    except Exception as e:
        logger.error(f"Failed to trigger Agent 3: {e}")
            
    # Note: To run this as a persistent service, uncomment the following:
    # schedule.every().day.at("02:00").do(agent.run_collection)
    # while True:
    #     schedule.run_pending()
    #     time.sleep(60)
