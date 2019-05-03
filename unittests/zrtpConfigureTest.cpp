//
// Created by Werner Dittmann on 2019-05-01.
//

#include "catch.hpp"
#include "../zrtp/libzrtpcpp/ZrtpConfigure.h"

using namespace std;

TEST_CASE("Test Hash setup") {

    ZrtpConfigure config;

    auto e = zrtpHashes.getByName("S256");
    REQUIRE(string("S256") == string(e.getName()));
    REQUIRE(HashAlgorithm == e.getAlgoType());

    REQUIRE((ZrtpConfigure::maxNoOfAlgos-1) == config.addAlgo(HashAlgorithm, e));

    auto e1 = zrtpHashes.getByName("S384");

    // Add new algorithm at position 0, thus before existing algorithm
    REQUIRE((ZrtpConfigure::maxNoOfAlgos-2) == config.addAlgoAt(HashAlgorithm, e1, 0));

    auto e2 = config.getAlgoAt(HashAlgorithm, 0);
    REQUIRE(string("S384") == string(e2.getName()));

    REQUIRE(2 == config.getNumConfiguredAlgos(HashAlgorithm));

    config.removeAlgo(HashAlgorithm, e2);
    e2 = config.getAlgoAt(HashAlgorithm, 0);
    REQUIRE(string("S256") == string(e2.getName()));

    config.clear();

    // cleared the configuration data only, global data should still be OK, check it
    auto e3 = zrtpHashes.getByName("S256");
    REQUIRE(string("S256") == string(e3.getName()));
    REQUIRE(HashAlgorithm == e3.getAlgoType());
}
