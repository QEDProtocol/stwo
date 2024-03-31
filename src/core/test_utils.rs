use super::backend::cpu::CPUCircleEvaluation;
use super::channel::Sha256Channel;
use super::fields::m31::BaseField;
use super::fields::qm31::SecureField;
use crate::core::channel::Channel;

pub fn secure_eval_to_base_eval<EvalOrder>(
    eval: &CPUCircleEvaluation<SecureField, EvalOrder>,
) -> CPUCircleEvaluation<BaseField, EvalOrder> {
    CPUCircleEvaluation::new(
        eval.domain,
        eval.values.iter().map(|x| x.to_m31_array()[0]).collect(),
    )
}

pub fn test_channel() -> Sha256Channel {
    use crate::commitment_scheme::sha256_hash::Sha256Hash;

    let seed = Sha256Hash::from(vec![0; 32]);
    Sha256Channel::new(seed)
}
