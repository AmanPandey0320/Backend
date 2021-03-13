const {createProvider,verifyProviderJWT,getProviderById,updateProvider,deleteProvider} = require('./provider.services');
const {verifyJWT} = require('../auth/auth.services');

module.exports = {
    createProvider: async (req, res) =>{
        const {token,aadhaar,pan,business_proof,business_location} = req.body;

        try{

            const authState = await verifyJWT(token);
            if(authState.code === 200){
                //verifid user 
                const user_id = authState.uid;

                createProvider({user_id,aadhaar,pan,business_proof,business_location},(err,info) =>{
                    if(err){
                        res.status(500).json(err);
                    }else{
                        res.status(200).json(info);
                    }
                });

            }else{
                //user not verified
                res.status(401).json({code: 401, message:'Please sign in or sign up to continue!'});
            }

        }catch(err){
            res.status(500).json({code:err.code, message:err.message});
        }
    },

    getProvider: async (req, res) =>{

        try{


            const {token,ptoken} = req.body;

            const userAuthState = await verifyJWT(token);

            if(userAuthState.code === 200){
                //user authenticate

                const providerAuthState = await verifyProviderJWT(ptoken);
                
                if(providerAuthState.code === 200){
                    //provider Verified
                    const {provider_id} = providerAuthState;
                    // console.log(providerAuthState);
                    getProviderById(provider_id,(err,info) =>{
                        if(err){
                            res.status(500).json(err);
                        }else{
                            res.status(200).json(info);
                        }
                    });
                }else{
                    //provider not Verified
                    res.status(401).json({code:401, message:'you are not a verified provider or you are tring to access a deleted account.'});
                }

            }else{
                //user not authenticated
                res.status(401).json({code:401, message:'can not verify you! Please sign in or sign up.'});
            }

        }catch(err){
            res.status(500).json({code:err.code, message:err.message,err:err})
        }
    },

    updateProvider: async (req, res) =>{
        const {ptoken,token,business_proof,business_location} = req.body;
         try{

            const userAuthState = await verifyJWT(token);

            if(userAuthState.code === 200){
                //user is verified  
                const providerAuthState = await verifyProviderJWT(ptoken);
                
                if(providerAuthState.code === 200){
                    //provider is verified

                    const {provider_id} = providerAuthState;
                    const data = {provider_id,business_proof,business_location};
                    updateProvider(data,(err,info)=>{
                        if(err){
                            res.status(500).json(err);
                        }else{
                            res.status(200).json(info);
                        }
                    });
                }else{
                    //provider is not verified
                    res.status(401).json({code:401, message:'you are not a verified provider or you are tring to access a deleted account.'});
                }

            }else{
                //user is not Verified
                res.status(401).json({code:401, message:'can not verify you! Please sign in or sign up.'})
            }

         }catch(err){
            //  console.log(err);
             res.status(500).json({code:err.code, message:err.message,err:err});
         }
    },
    
    deleteProvider: async (req, res) =>{
        const {token,ptoken}=req.body;

        try {

            const userAuthState = await verifyJWT(token);

            if(userAuthState.code === 200){

                const providerAuthState = await verifyProviderJWT(ptoken);

                if(providerAuthState.code === 200){

                    deleteProvider(providerAuthState.provider_id,(err,info) =>{
                        if(err){
                            res.status(500).json(err);
                        }else{
                            res.status(200).json(info);
                        }
                    });

                }else{
                    res.status(401).json({code:401, message:'provider not verified'});
                }

            }else{
                //user not verified
                res.status(401).json({code:401, message:'not a verified user'});
            }
            
        } catch (err) {
            console.log(err);
            res.status(500).json(err);
        }
    }
}