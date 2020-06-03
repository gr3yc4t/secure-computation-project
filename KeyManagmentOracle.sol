pragma experimental ABIEncoderV2;

import "verifier.sol";

/// @title Implementation of the Key Management Oracle for redactable blockchains
contract KeyManagement is Verifier{

    struct Collision{
        uint128 collisionIndex;     //The i-th collision index
        uint256 collisionKey0;       //The c_i_0 value
        uint256 collisionKey1;       //The c_i_1 value
        uint256 collisionSignature; //Hash(m || i)
        uint256 blockNumber;
        bytes32 reason;             //A string that briefly explain the reason for the redactable-blockchain modification
    }

    struct Commitment{
        uint256 commitment;         //The commitment of the chameleon hash trapdoor key

        //Pedersen Commitment parameters
        uint256 g;
        uint256 h;
    }


    event CollisionPerformed(uint256 blockNumber, uint128 collisionIndex);

    event CollisionUnlocked(uint256 blockNumber);



    Commitment trapdoor;    //Commitment to the trapdoor c0
    uint128 k;              //The number of times a block can be redacted

    //Ledger that contains all the collision occurred so far
    mapping (uint256 => Collision[]) private collision_ledger;

    //Mapping that contains the randomness to "unlock" collisions for the block i
    mapping (uint256 => bytes32) private chameleon_randomness;


    /// @param _commitment  A Pedersen commitment to the trapdoor key (c0)
    /// @param _g           Pedersen commitment parameter
    /// @param _h           Pedersen commitment parameter
    /// @param _k           Paramater of the scheme, indicates the number of times a block can be redacted
    constructor (uint256 _commitment, uint256 _g, uint256 _h, uint128 _k) public {
        k = _k;

        Commitment memory _trapdoor;

        _trapdoor.commitment = _commitment;
        _trapdoor.g = _g;
        _trapdoor.h = _h;

        trapdoor = _trapdoor;
    }

    //TODO: Add an option where the collider must stake its money to perform a collision
    //TODO: Remove the constraint of 16 variables (cannot provide "reason")
    /**
     * Zokrates Inputs:
     *  - c0          -> _collisionKey1
     *  - c1          -> _collisionKey2
     *  - keyIndex    -> function input "collisionIndex"
     *  - blockNumber -> function input
     *  - commitment  -> present on contract
     *  - G           -> present on contract
     *  - h           -> present on contract
     *  - (private) message
     *  - (private) randomness
     *  - Last input = zookrates return = 1
     */


    /// Function that implements the "Collision" query of the Key Management Oracle
    /// @param _blockNumber     Block where the collision is performed
    /// @param _collisionKey1   First part of the i-th collision key
    /// @param _collisionKey1   Second part of the i-th collision key
    /// @param _collisionIndex  The index i of the collision key
    /// @param _collisionSignature Signature of the performed collision H( c_i || m)
    /// @param _a               Parameter A of the zk-SNARK proof
    /// @param _b               Parameter B of the zk-SNARK proof
    /// @param _c               Parameter C of the zk-SNARK proof
    /// @return bool            True if the provided parameter are correct, exception in any other case
    ///

    /// @dev This function initially checks if the collision for the provided block are already unlocked,
    ///     otherwise it triggers an assertion. Then it gets the collision key has the right index and,
    ///     finally, it check the proof. If everything is ok it add the collision to the storage.
    ///
    /// @TODO Take "string reason" as aa parameter for the collision
    function FinalizeCollision(
        uint256 _blockNumber, uint256 _collisionKey1, uint256 _collisionKey2, uint128 _collisionIndex, uint256 _collisionSignature,
        uint[2] memory _a, uint[2][2] memory _b, uint[2] memory _c
    ) public returns (bool){

        require(isBlockCollisionUnlocked(_blockNumber), "Block not unlocked");

        //Start checks
        Collision memory last_collision;
        bool collisionExists;

        (collisionExists, last_collision) = this.getLastCollision(_blockNumber);

        if (collisionExists){
            require(_collisionIndex == last_collision.collisionIndex + 1, "Invalid Index");  //Ensure that the new collision is performed with the next collision key
        }else{
            require(_collisionIndex == k-2, "Invalid first collision key");
        }

        uint[8] memory proof_input;

        proof_input[0] = _collisionKey1;
        proof_input[1] = _collisionKey2;
        proof_input[2] = _collisionIndex;
        proof_input[3] = _blockNumber;
        proof_input[4] = trapdoor.commitment;
        proof_input[5] = trapdoor.g;
        proof_input[6] = trapdoor.h;
        proof_input[7] = 1;                 //Return value of Zokrates


        //Check Proof
        bool proof_result = verifyTx(_a, _b, _c, proof_input);

        require(proof_result, "Proof not valid");

        Collision memory new_collision;

        new_collision.collisionIndex = _collisionIndex;
        new_collision.collisionKey0 = _collisionKey1;
        new_collision.collisionKey1 = _collisionKey2;
        new_collision.collisionSignature = _collisionSignature;
        new_collision.blockNumber = _blockNumber;
        new_collision.reason = "";


        collision_ledger[_blockNumber].push(new_collision);

        emit CollisionPerformed(_blockNumber, _collisionIndex);

        return true;
    }


    /// Unlock the k-collision via the computed randomness of the chameleon hash
    /// @param _blockNumber The block to unlock
    /// @param _randomness  The randomness of the chameleon hash
    /// @return bool        True if everything is ok, an assertion is triggered if the block is already unlocked
    /// @TODO Add a check to verity that the provided randomness is valid
    function unlockBlockCollisions(uint256 _blockNumber, bytes32 _randomness) public returns (bool){

        require(!isBlockCollisionUnlocked(_blockNumber), "Block already unlocked");

        chameleon_randomness[_blockNumber] = _randomness;

        emit CollisionUnlocked(_blockNumber);

        return true;
    }

    // ---------------------------------------------------------------------------------------------------------
    //                                              GET METHODS
    // ---------------------------------------------------------------------------------------------------------


    function getCommitment() external view returns(uint256, uint256, uint256){
        return (trapdoor.commitment, trapdoor.g, trapdoor.h);
    }


    function getChameleonRandomness(uint256 _blockNumber) external view returns (bytes32){
        return chameleon_randomness[_blockNumber];
    }


    function isBlockCollisionUnlocked(uint256 _blockNumber) public view returns (bool){
        bytes32 rand = chameleon_randomness[_blockNumber];

        if (rand == 0){
            return false;
        }
        return true;
    }

    ///Return the last collision performed on a block
    /// @param _blockNumber The block to inspect
    /// @return bool        true if a collision exists, false otherwise
    /// @return Collision   The last performed collision, if not exists an invalid collision
    /// @dev    In case no collision is present, the first param is set to false and the returned
    ///         collision structure is filled with invalid data
    function getLastCollision(uint256 _blockNumber) external view returns (bool, Collision memory){

        require(isBlockCollisionUnlocked(_blockNumber), "Block not unlocked");

        Collision[] memory blockCollisions = collision_ledger[_blockNumber];

        uint len = blockCollisions.length;

        if (len > 0){
            return (true, blockCollisions[len-1]);  //Return last collision
        }else{

            Collision memory empty;

            empty.collisionIndex = k+1;     //To make it invalid
            empty.blockNumber = 0;

            return (false, empty);
        }
    }


    /// Check if a collision signature ( H( m || i) ) is valid
    /// @param _blockNumber The block to check
    /// @param _data        The collision signature to check
    /// @dev Search _data in the block's collisions mapping
    function isValid(uint256 _blockNumber, uint256 _data) external view returns (bool){

        Collision[] memory collisions = collision_ledger[_blockNumber];

        uint collision_number = collisions.length;

        for (uint i = 0; i<collision_number; i++){

            if( collisions[i].collisionSignature == _data ){
                return true;
            }

        }

        return false;
    }

}