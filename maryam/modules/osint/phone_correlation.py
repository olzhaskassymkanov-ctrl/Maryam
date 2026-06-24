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
	'name': 'Phone Number Correlation',
	'author': 'OSINT Team',
	'version': '1.0',
	'description': 'Analyze and establish connections between multiple phone numbers. Identifies patterns, operators, regions, and correlations.',
	'sources': ('phone_analysis'),
	'options': (
		('numbers', None, True, 'Comma-separated phone numbers (e.g. 77470736288,77085624710)', '-n', 'store', str),
		('analysis_type', 'full', False, 'Analysis type: full, pattern, operator, region (default=full)', '-t', 'store', str),
	),
	'examples': ('phone_correlation -n 77470736288,77085624710,77070152777',
		'phone_correlation -n 77470736288,77085624710 -t pattern')
}

class PhoneAnalyzer:
	"""Analyze phone numbers and find correlations"""
	
	# Kazakhstan operator codes mapping
	OPERATORS = {
		'701': {'operator': 'Activ', 'type': 'GSM', 'region': 'National'},
		'702': {'operator': 'Activ', 'type': 'GSM', 'region': 'National'},
		'703': {'operator': 'Activ', 'type': 'GSM', 'region': 'National'},
		'704': {'operator': 'Activ', 'type': 'GSM', 'region': 'National'},
		'705': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'706': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'707': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'708': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'709': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'710': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'711': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'712': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'713': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'714': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'715': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'716': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'717': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'718': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'719': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'720': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'721': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'722': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'723': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'724': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'725': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'726': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'727': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'728': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'729': {'operator': 'Kcell', 'type': 'GSM', 'region': 'National'},
		'775': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'776': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'777': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'778': {'operator': 'Beeline', 'type': 'GSM', 'region': 'National'},
		'779': {'operator': 'Activ', 'type': 'GSM', 'region': 'National'},
		'780': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'781': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'782': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'783': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'784': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'785': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'786': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'787': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'788': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
		'789': {'operator': 'Tele2', 'type': 'GSM', 'region': 'National'},
	}
	
	def __init__(self, phone_numbers):
		"""Initialize with list of phone numbers"""
		self.phone_numbers = [str(num).strip() for num in phone_numbers if num.strip()]
		self.normalized_numbers = [self._normalize(num) for num in self.phone_numbers]
		self.analysis_results = {}
	
	def _normalize(self, number):
		"""Normalize phone number to standard format"""
		# Remove all non-digit characters
		clean = ''.join(filter(str.isdigit, str(number)))
		
		# If it's 10 digits (without country code), assume it's Kazakhstan (7)
		if len(clean) == 10:
			clean = '7' + clean
		
		return clean
	
	def _get_operator_info(self, number):
		"""Get operator information from phone number"""
		normalized = self._normalize(number)
		if len(normalized) >= 4:
			operator_code = normalized[1:4]  # Extract 3 digits after country code
			return self.OPERATORS.get(operator_code, {'operator': 'Unknown', 'type': 'Unknown', 'region': 'Unknown'})
		return {'operator': 'Unknown', 'type': 'Unknown', 'region': 'Unknown'}
	
	def _extract_pattern(self, number):
		"""Extract patterns from phone number"""
		normalized = self._normalize(number)
		if len(normalized) >= 11:
			operator_code = normalized[1:4]
			area_code = normalized[4:7]
			exchange = normalized[7:10]
			subscriber = normalized[10:11]
			return {
				'operator_code': operator_code,
				'area_code': area_code,
				'exchange': exchange,
				'subscriber_prefix': subscriber
			}
		return {}
	
	def analyze_pattern(self):
		"""Analyze patterns in phone numbers"""
		if not self.normalized_numbers:
			return {'error': 'No valid phone numbers provided'}
		
		patterns = []
		for i, number in enumerate(self.phone_numbers):
			pattern = self._extract_pattern(number)
			pattern['original'] = number
			pattern['normalized'] = self.normalized_numbers[i]
			pattern['operator'] = self._get_operator_info(number)
			patterns.append(pattern)
		
		return {'patterns': patterns, 'count': len(patterns)}
	
	def analyze_operator(self):
		"""Analyze operator distribution"""
		operator_groups = {}
		
		for number in self.phone_numbers:
			op_info = self._get_operator_info(number)
			operator = op_info['operator']
			
			if operator not in operator_groups:
				operator_groups[operator] = {
					'count': 0,
					'numbers': [],
					'info': op_info
				}
			
			operator_groups[operator]['count'] += 1
			operator_groups[operator]['numbers'].append(number)
		
		return {
			'operator_distribution': operator_groups,
			'total_operators': len(operator_groups),
			'total_numbers': len(self.phone_numbers)
		}
	
	def analyze_region(self):
		"""Analyze region distribution"""
		regions = {}
		
		for number in self.phone_numbers:
			normalized = self._normalize(number)
			if len(normalized) >= 7:
				area_code = normalized[4:7]
				
				if area_code not in regions:
					regions[area_code] = {
						'area_code': area_code,
						'count': 0,
						'numbers': []
					}
				
				regions[area_code]['count'] += 1
				regions[area_code]['numbers'].append(number)
		
		return {
			'regions': regions,
			'total_regions': len(regions),
			'total_numbers': len(self.phone_numbers)
		}
	
	def analyze_correlation(self):
		"""Analyze correlations between numbers"""
		if len(self.normalized_numbers) < 2:
			return {'error': 'Need at least 2 numbers for correlation analysis'}
		
		correlations = {
			'same_operator': [],
			'same_area_code': [],
			'sequential_exchanges': [],
			'similar_patterns': []
		}
		
		# Check for same operator
		for i in range(len(self.phone_numbers)):
			for j in range(i+1, len(self.phone_numbers)):
				op1 = self._get_operator_info(self.phone_numbers[i])
				op2 = self._get_operator_info(self.phone_numbers[j])
				
				if op1['operator'] == op2['operator'] and op1['operator'] != 'Unknown':
					correlations['same_operator'].append({
						'number1': self.phone_numbers[i],
						'number2': self.phone_numbers[j],
						'operator': op1['operator']
					})
				
				# Check for same area code
				norm1 = self.normalized_numbers[i]
				norm2 = self.normalized_numbers[j]
				
				if len(norm1) >= 7 and len(norm2) >= 7:
					if norm1[4:7] == norm2[4:7]:
						correlations['same_area_code'].append({
							'number1': self.phone_numbers[i],
							'number2': self.phone_numbers[j],
							'area_code': norm1[4:7]
						})
					
					# Check for sequential exchanges (within 5 of each other)
					ex1 = int(norm1[7:10])
					ex2 = int(norm2[7:10])
					if abs(ex1 - ex2) <= 5:
						correlations['sequential_exchanges'].append({
							'number1': self.phone_numbers[i],
							'number2': self.phone_numbers[j],
							'exchange1': ex1,
							'exchange2': ex2,
							'difference': abs(ex1 - ex2)
						})
		
		return correlations
	
	def full_analysis(self):
		"""Perform comprehensive analysis"""
		return {
			'summary': {
				'total_numbers': len(self.phone_numbers),
				'all_normalized': self.normalized_numbers
			},
			'patterns': self.analyze_pattern(),
			'operators': self.analyze_operator(),
			'regions': self.analyze_region(),
			'correlations': self.analyze_correlation()
		}

def module_api(self):
	"""Module API function"""
	numbers_str = self.options['numbers']
	analysis_type = self.options['analysis_type'].lower()
	
	# Parse numbers
	numbers = [n.strip() for n in numbers_str.split(',')]
	
	# Create analyzer
	analyzer = PhoneAnalyzer(numbers)
	
	# Perform analysis based on type
	if analysis_type == 'pattern':
		output = analyzer.analyze_pattern()
	elif analysis_type == 'operator':
		output = analyzer.analyze_operator()
	elif analysis_type == 'region':
		output = analyzer.analyze_region()
	elif analysis_type == 'correlation':
		output = analyzer.analyze_correlation()
	else:  # full analysis
		output = analyzer.full_analysis()
	
	# Save results
	target_key = f"phone_correlation_{analysis_type}"
	self.save_gather(output, 'osint/phone_correlation', target_key, output=self.options['output'])
	
	return output

def module_run(self):
	"""Module run function"""
	output = module_api(self)
	self.alert_results(output)
