mu =0.25
omega=10

redundant_groups = [
    #('c1', 'c2','c3') #TestCase 6
    #('c1','c2','c3','c4')#TestCase 7
    #('c1','c2')#TestCase 8
    ('c1','c2','c3', 'c4','c5')  # TestCase 8
]

asset_impacts = {
    #'c1': {'max_read_impact': 1, 'max_write_impact': 5},#TestCase 6
    #'c2': {'max_read_impact': 5, 'max_write_impact': 2},#TestCase 6
    #'c3': {'max_read_impact': 3, 'max_write_impact': 3}#TestCase 6

    'c1': {'max_read_impact': 1, 'max_write_impact': 5},#TestCase 7
    'c2': {'max_read_impact': 5, 'max_write_impact': 2},#TestCase 7
    'c3': {'max_read_impact': 3, 'max_write_impact': 3},#TestCase 7
    'c4': {'max_read_impact': 3, 'max_write_impact': 4},#TestCase 7
    'c5': {'max_read_impact': 4, 'max_write_impact': 1},#TestCase 7
    'c6': {'max_read_impact': 5, 'max_write_impact': 3},#TestCase 7
    'c7': {'max_read_impact': 1, 'max_write_impact': 2},#TestCase 7
    'c8': {'max_read_impact': 2, 'max_write_impact': 4}#TestCase 7
}

vulnerability_features_scores={
    'zero_trust':1,
    'mac':3,
    'dynamic_mac':20
}
logging_features_scores={
    'zero_trust_logger': .5,
    'some_logging': 1,
    'no_logging': 2
}

vulnerability_features = {
    #'c1': 1,#TestCase 6
    #'c2': 1,#TestCase 6
    #'c3': 1,#TestCase 6
    'c1': 1,#TestCase 7
    'c2': 1,#TestCase 7
    'c3': 1,#TestCase 7
    'c4': 1,#TestCase 7
    'c5': 1,#TestCase 7
    'c6': 1,#TestCase 7
    'c7': 1,#TestCase 7
    'c8': 1,#TestCase 7
    'default_value': 1
}

logging_features = {
    #'c1': .5,#TestCase 6
    #'c2': .5,#TestCase 6
    #'c3': .5,#TestCase 6
    'c1': .5,#TestCase 7
    'c2': .5,#TestCase 7
    'c3': .5,#TestCase 7
    'c4': .5,#TestCase 7
    'c5': .5,#TestCase 7
    'c6': .5,#TestCase 7
    'c7': .5,#TestCase 7
    'c8': .5,#TestCase 7
    'default_value': 1
}


#for component, asset_dict in asset_impacts.items():
    #print(f'Component: {component}')
    #for inner_key, value in asset_dict.items():
        #print(f'  Asset: {inner_key}, Impact: {value}')


new_dict = {}

for component, impacts in asset_impacts.items():
    new_dict[component] = {
        'impacts': impacts,
        'vulnerability_score': vulnerability_features.get(component, vulnerability_features.get('default_value')),
        'logging_score': logging_features.get(component, logging_features.get('default_value')),
        'original_risk': {'og_read_risk': 0, 'og_write_risk': 0, 'og_prob':0, 'og_prob_normalized':0},
        'new_risk': {'new_read_risk': 0, 'new_write_risk': 0, 'new_denorm_prob': 0, 'new_prob_normalized':0}
    }

for component, data in new_dict.items():
    impacts = data['impacts']

    # Initialize impact values
    read_impact = 0
    write_impact = 0

    # Find read and write impacts
    for key, value in impacts.items():
        if 'read' in key:
            read_impact = value
        elif 'write' in key:
            write_impact = value

    # Calculate risks
    data['original_risk']['og_read_risk'] = read_impact * data['vulnerability_score'] * data['logging_score']
    data['original_risk']['og_write_risk'] = write_impact * data['vulnerability_score'] * data['logging_score']

# Calculate original probablities and convert them to the normalized
for component, data in new_dict.items():
    vuln = data['vulnerability_score']
    log = data['logging_score']
    og_prob = vuln * log
    data['original_risk']['og_prob'] = og_prob

    # Next calculate normalized probablity
    og_prob_normalized = (og_prob-mu)/(omega-mu)
    data['original_risk']['og_prob_normalized'] = og_prob_normalized



# Calculate new_probabilities based off the normalized probability
for group in redundant_groups:
    combined_prob_norm = 1
    for comp in group:
        combined_prob_norm *= new_dict[comp]['original_risk'].get('og_prob_normalized', 0)

    for comp in group:
        new_dict[comp]['new_risk']['new_prob_normalized'] = combined_prob_norm

# Calculate denormalized probabilities
for component, data in new_dict.items():
    new_prob_norm = data['new_risk'].get('new_prob_normalized', 0)
    if new_prob_norm == 0:
        new_denorm_prob = data['original_risk'].get('og_prob', 0)
    else:
        new_denorm_prob = new_prob_norm * (omega - mu) + mu
    data['new_risk']['new_denorm_prob'] = new_denorm_prob

# Calculate the new read and write risk for each component
for component, data in new_dict.items():
    impacts = data['impacts']
    new_prob_denorm = data['new_risk'].get('new_denorm_prob', 0)

    read_impact = impacts.get('max_read_impact', 0)
    write_impact = impacts.get('max_write_impact', 0)

    data['new_risk']['new_read_risk'] = read_impact * new_prob_denorm
    data['new_risk']['new_write_risk'] = write_impact * new_prob_denorm

for comp, data in new_dict.items():
    print(f'Component: {comp}')
    for key, value in data.items():
        print(f'  {key}: {value}')
    print()