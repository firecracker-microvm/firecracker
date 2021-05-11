all
rule 'MD013', :tables => false

exclude_rule 'MD033'
exclude_rule 'MD041'
exclude_rule 'MD024'
exclude_rule 'MD026'
exclude_rule 'MD002'

# Some markdown code blocks are not strictly adhering to a language.
# For example, we may add comments to JSON code blocks that are not supported
# in the JSON format.
exclude_rule 'MD040' # Fenced code blocks should have a language specified.
