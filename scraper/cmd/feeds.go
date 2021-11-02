package cmd

import (
	"nanscraper/pkg/feeders"
	"nanscraper/pkg/feeders/appleadv"
)

var feedSources []feeders.Feeder

func initFeeds() {
	// The order here is the order that the VulnDB will be prepared in.
	feedSources = []feeders.Feeder{
		appleadv.New(),
	}
}
