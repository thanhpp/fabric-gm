/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msptesttools

import (
	"log"

	"github.com/m4ru1/fabric-gm-bdais/bccsp/factory"
	"github.com/m4ru1/fabric-gm-bdais/core/config/configtest"
	"github.com/m4ru1/fabric-gm-bdais/msp"
	"github.com/m4ru1/fabric-gm-bdais/msp/mgmt"
)

// LoadTestMSPSetup sets up the local MSP
// and a chain MSP for the default chain
func LoadMSPSetupForTesting() error {
	dir := configtest.GetDevMspDir()
	conf, err := msp.GetLocalMspConfig(dir, nil, "SampleOrg")
	if err != nil {
		return err
	}
	log.Println("LoadMSPSetupForTesting", "dir", dir)

	log.Println("load msp setup for testing", "conf", conf)

	err = mgmt.GetLocalMSP(factory.GetDefault()).Setup(conf)
	if err != nil {
		return err
	}

	err = mgmt.GetManagerForChain("testchannelid").Setup([]msp.MSP{mgmt.GetLocalMSP(factory.GetDefault())})
	if err != nil {
		return err
	}

	return nil
}
