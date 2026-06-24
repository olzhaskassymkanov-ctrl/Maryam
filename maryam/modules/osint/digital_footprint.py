"""
OWASP Maryam!

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

meta = {
	'name': 'Digital Footprint Analysis',
	'author': 'OSINT Team',
	'version': '1.0',
	'description': 'Comprehensive analysis of digital footprint across multiple legal public sources. Correlate usernames and identify connections.',
	'sources': ('public_web'),
	'options': (
		('identifier', None, True, 'Username, email, or domain to analyze', '-i', 'store', str),
		('analysis_depth', 'standard', False, 'Analysis depth: quick, standard, or deep (default=standard)', '-d', 'store', str),
	),
	'examples': ('digital_footprint -i winxpsp1',
		'digital_footprint -i winxpsp1 -d deep --output',
		'digital_footprint -i user@example.com')
}

class DigitalFootprintAnalyzer:
	"""Analyze digital footprint using legal public sources"""
	
	# Public OSINT databases and archives
	ARCHIVE_SOURCES = {
		'wayback_machine': {
			'name': 'Wayback Machine',
			'url': 'https://web.archive.org/web/*/{}',
			'description': 'Historical snapshots of web pages',
			'legal': True
		},
		'google_cache': {
			'name': 'Google Cache',
			'url': 'https://webcache.googleusercontent.com/cache:{}',
			'description': 'Cached versions of web pages',
			'legal': True
		}
	}
	
	# Search engines with advanced operators
	SEARCH_STRATEGIES = {
		'direct_search': [
			'"{}" -site:facebook.com',
			'{} telegram',
			'{} github',
			'{} linkedin',
			'{} twitter',
		],
		'email_search': [
			'"{}" email',
			'"{}" @gmail.com',
			'"{}" @outlook.com',
			'"{}" contact',
		],
		'code_search': [
			'site:github.com "{}"',
			'site:gitlab.com "{}"',
			'site:pastebin.com "{}"',
		],
		'document_search': [
			'filetype:pdf "{}"',
			'filetype:doc "{}"',
			'filetype:xls "{}"',
		],
		'social_media': [
			'site:twitter.com {}',
			'site:reddit.com {}',
			'site:instagram.com {}',
			'site:youtube.com {}',
		]
	}
	
	# Public databases and registries
	PUBLIC_DATABASES = {
		'whois': {
			'name': 'WHOIS Database',
			'url': 'https://www.whois.com/whois/{}',
			'type': 'domain_registry'
		},
		'crt_sh': {
			'name': 'Certificate Transparency (crt.sh)',
			'url': 'https://crt.sh/?q={}',
			'type': 'certificate_registry'
		},
		'shodan': {
			'name': 'SHODAN',
			'url': 'https://www.shodan.io/search?query={}',
			'type': 'iot_search'
		},
		'github_search': {
			'name': 'GitHub Advanced Search',
			'url': 'https://github.com/search?q={}',
			'type': 'code_repository'
		},
		'linkedin': {
			'name': 'LinkedIn',
			'url': 'https://www.linkedin.com/search/results/people/?keywords={}',
			'type': 'professional_network'
		}
	}
	
	# Social media platforms
	SOCIAL_PLATFORMS = {
		'telegram': 'https://t.me/{}',
		'twitter': 'https://twitter.com/{}',
		'reddit': 'https://reddit.com/u/{}',
		'github': 'https://github.com/{}',
		'linkedin': 'https://linkedin.com/in/{}',
		'youtube': 'https://youtube.com/@{}',
		'instagram': 'https://instagram.com/{}',
		'facebook': 'https://facebook.com/{}',
		'tiktok': 'https://tiktok.com/@{}',
	}
	
	def __init__(self, identifier):
		"""Initialize with identifier (username, email, or domain)"""
		self.identifier = identifier.strip()
		self.cleaned_identifier = self.identifier.lstrip('@')
		self.type = self._detect_type()
	
	def _detect_type(self):
		"""Detect identifier type"""
		if '@' in self.identifier:
			return 'email'
		elif '.' in self.identifier and not self.identifier.startswith('@'):
			return 'domain'
		else:
			return 'username'
	
	def generate_search_urls(self):
		"""Generate comprehensive search URLs"""
		urls = {}
		
		# Social media searches
		urls['social_platforms'] = []
		for platform, url_template in self.SOCIAL_PLATFORMS.items():
			urls['social_platforms'].append({
				'platform': platform,
				'url': url_template.format(self.cleaned_identifier),
				'description': f'Search on {platform.title()}'
			})
		
		# Archive searches
		urls['archives'] = []
		for key, source in self.ARCHIVE_SOURCES.items():
			urls['archives'].append({
				'source': source['name'],
				'url': source['url'].format(self.cleaned_identifier),
				'description': source['description']
			})
		
		# Public databases
		urls['databases'] = []
		for key, db in self.PUBLIC_DATABASES.items():
			urls['databases'].append({
				'database': db['name'],
				'url': db['url'].format(self.cleaned_identifier),
				'type': db['type']
			})
		
		return urls
	
	def get_google_dorks(self):
		"""Generate Google search dorks"""
		dorks = []
		
		for category, search_list in self.SEARCH_STRATEGIES.items():
			dorks.append({
				'category': category,
				'queries': [q.format(self.cleaned_identifier) for q in search_list]
			})
		
		return dorks
	
	def analyze_username_patterns(self):
		"""Analyze patterns in username"""
		analysis = {
			'identifier': self.identifier,
			'type': self.type,
			'characteristics': {
				'length': len(self.cleaned_identifier),
				'contains_numbers': any(c.isdigit() for c in self.cleaned_identifier),
				'contains_special': any(not c.isalnum() for c in self.cleaned_identifier),
				'starts_with_capital': self.cleaned_identifier[0].isupper() if self.cleaned_identifier else False,
			},
			'potential_clues': []
		}
		
		# Analyze for patterns
		if 'win' in self.cleaned_identifier.lower():
			analysis['potential_clues'].append('Contains "win" - may reference Windows or gaming')
		if any(c.isdigit() for c in self.cleaned_identifier):
			numbers = ''.join(filter(str.isdigit, self.cleaned_identifier))
			analysis['potential_clues'].append(f'Contains numbers: {numbers}')
		if '_' in self.cleaned_identifier:
			analysis['potential_clues'].append('Uses underscore - formal or technical username')
		
		return analysis
	
	def get_correlation_points(self):
		"""Identify potential correlation points"""
		correlations = {
			'exact_match': f'Search for exact username: {self.cleaned_identifier}',
			'variations': [
				self.cleaned_identifier.replace('_', '.'),
				self.cleaned_identifier.replace('_', '-'),
				self.cleaned_identifier.upper(),
				self.cleaned_identifier.title(),
			],
			'common_combinations': [
				f'{self.cleaned_identifier}123',
				f'{self.cleaned_identifier}2020',
				f'{self.cleaned_identifier}2021',
				f'{self.cleaned_identifier}2022',
			]
		}
		return correlations
	
	def full_analysis(self, depth='standard'):
		"""Perform comprehensive digital footprint analysis"""
		analysis = {
			'target': self.identifier,
			'identifier_type': self.type,
			'analysis_depth': depth,
			'pattern_analysis': self.analyze_username_patterns(),
			'search_urls': self.generate_search_urls(),
			'google_dorks': self.get_google_dorks(),
			'correlation_points': self.get_correlation_points(),
			'methodology': [
				'Step 1: Verify the identifier exists on social platforms',
				'Step 2: Check archive.org for historical profiles',
				'Step 3: Search across all major platforms using Google dorks',
				'Step 4: Look for username variations and similar accounts',
				'Step 5: Correlate findings across platforms',
				'Step 6: Document timeline and connections',
				'Step 7: Verify information through multiple sources',
				'Step 8: Compile findings into comprehensive report'
			],
			'tools_recommendation': [
				'Sherlock - Fastest username search across 300+ sites',
				'Hunter.io - Email finder and verification',
				'Reverse Image Search - Google, Bing, TinEye',
				'Maltego - Link analysis and OSINT automation',
				'SpiderFoot - Automated OSINT tool',
				'OSINT Framework - Online tools aggregator'
			],
			'legal_notice': [
				'✓ All sources are publicly accessible',
				'✓ No unauthorized access attempted',
				'✓ Respects terms of service of each platform',
				'✓ Complies with data protection regulations',
				'✓ Used for legitimate research purposes only',
				'✓ Findings are based on public information'
			],
			'next_steps': [
				'1. Visit each URL manually to verify',
				'2. Take screenshots or archive results',
				'3. Look for connected accounts and cross-references',
				'4. Check profile metadata and activity',
				'5. Correlate information to build timeline',
				'6. Document all findings with sources',
				'7. Verify through independent sources',
				'8. Create comprehensive report'
			]
		}
		
		if depth == 'deep':
			analysis['advanced_techniques'] = {
				'reverse_image_search': 'Check if profile pictures appear elsewhere',
				'email_to_username': 'If email found, search for associated usernames',
				'phone_verification': 'Check if phone number is listed publicly',
				'social_graph': 'Map connections and followers',
				'activity_analysis': 'Check posting patterns and interests',
				'geo_location': 'Identify location clues from posts',
				'language_analysis': 'Analyze writing patterns and language'
			}
		
		return analysis

def module_api(self):
	"""Module API function"""
	identifier = self.options['identifier']
	depth = self.options['analysis_depth'].lower()
	
	# Create analyzer
	analyzer = DigitalFootprintAnalyzer(identifier)
	
	# Perform analysis
	output = analyzer.full_analysis(depth)
	
	# Save results
	self.save_gather(output, 'osint/digital_footprint', identifier, output=self.options['output'])
	
	return output

def module_run(self):
	"""Module run function"""
	output = module_api(self)
	self.alert_results(output)
