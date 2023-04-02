pragma solidity ^0.4.6;

contract Rouleth {
    uint256 private seed;

    function Rouleth() public {
        seed = uint256(keccak256(block.timestamp));
    }

    function bet(uint256 guess) external payable {
        require(msg.value > 0, "Must bet a positive amount.");
        require(guess > 0 && guess <= 100, "Guess must be between 1 and 100.");

        seed = uint256(keccak256(block.timestamp, seed, block.difficulty));
        uint256 randomNumber = (uint256(block.blockhash(block.number - 1)) + seed) % 100 + 1;

        if (guess == randomNumber) {
            uint256 payout = msg.value * 98;
            if (payout + msg.value < msg.value) {
                payout = 0;
            } else {
                payout = payout / 100;
            }

            msg.sender.transfer(payout);
        }
    }
}
