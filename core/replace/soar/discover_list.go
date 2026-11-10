package soar

// List returns the resolvers discovery would vet, in the order it vets them: cached, Candidates,
// the device's own, the country's bundled list, global public resolvers, then addresses sampled
// from the country's ranges (SampleRanges). It lets a caller that spreads queries over resolvers
// itself, such as a resolver pool, use the same candidates.
func (d Discovery) List() []string {
	d.setDefaults()
	return d.candidates()
}
