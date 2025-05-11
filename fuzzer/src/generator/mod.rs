mod attribute;
pub mod grammar;
pub mod mutator;
pub mod transition;
pub mod utils;

use std::marker::PhantomData;
use libafl::{
    generators::Generator,
    state::HasRand,
    Error,
};
use libafl_bolts::HasLen;

use crate::{generator::grammar::{LorisBaseGrammarGenerator, LorisFastGrammarGenerator, LorisFastGrammarGenerator2,
              LorisGrammarGenerator}, input::vendor::shannon::smpf::SmpfEvent};
use crate::grammar::{
    base::LorisBaseGrammar,
    fast::LorisFastGrammar,
    fast2::LorisFastGrammar2,
    LorisGrammar,
};
use crate::input::{
    grammar::FastGrammarInput,
    LorisInput,
    vendor::{
        shannon::{
            qitem::{QItem, QItemField, QItemPDU},
            smpf::SmpfEventPaylod,
            ShannonInput,
        },
        VendorInput,
    },
};

pub struct LorisGenerator<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S>,
    G: LorisGrammar,
    S: HasRand,
{
    /// The grammar generator
    gg: GG,
    phantom: PhantomData<(&'a G, S)>,
}

impl<'a, GG, G, S> Generator<LorisInput, S> for LorisGenerator<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn generate(&mut self, state: &mut S) -> Result<LorisInput, Error> {
        let ex = self.generate_firmwire_ex(state);
        Ok(ex)
    }
}

impl<'a, S> From<&'a LorisBaseGrammar> for LorisGenerator<'a, LorisBaseGrammarGenerator<'a, S>, LorisBaseGrammar, S>
where
    S: HasRand,
{
    fn from(grammar: &'a LorisBaseGrammar) -> Self {
        Self {
            gg: LorisBaseGrammarGenerator::from_grammar(grammar),
            phantom: PhantomData,
        }
    }
}

impl<'a, S> From<&'a LorisFastGrammar> for LorisGenerator<'a, LorisFastGrammarGenerator<'a, S>, LorisFastGrammar, S>
where
    S: HasRand,
{
    fn from(grammar: &'a LorisFastGrammar) -> Self {
        Self {
            gg: LorisFastGrammarGenerator::from_grammar(grammar),
            phantom: PhantomData,
        }
    }
}

impl<'a, S> From<&'a LorisFastGrammar2> for LorisGenerator<'a, LorisFastGrammarGenerator2<'a, S>, LorisFastGrammar2, S>
where
    S: HasRand,
{
    fn from(grammar: &'a LorisFastGrammar2) -> Self {
        Self {
            gg: LorisFastGrammarGenerator2::from_grammar(grammar),
            phantom: PhantomData,
        }
    }
}

impl<'a, GG, G, S> LorisGenerator<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn generate_firmwire_ex(
        &self,
        state: &mut S
    ) -> LorisInput {
        // prepare mmc_emm_init_req
        let mut mmc_emm_init_req = QItem::from_qid(0xbc, 0x18, 0x3c5c);
        mmc_emm_init_req.push_payload_field(QItemPDU::array_from_vec(vec![0, 0, 0, 0, 0, 1, 0, 2, 0, 0, 1, 0, 3, 0]));

        // prepare SIM_MM_READ_ALL_MM_DATA_RSP
        let mut sim_mm_read_all_mm_data_rsp = QItem::from_qid(0x2e, 0x18, 0x3cc0);
        let mut payload = vec![0; 0x658];
        payload[0] = 1;  // CMD_SUCCESSFUL
        payload[1] = 0;  // != 1
        let imsi = vec![0x01, 0x10, 0x02, 0x00, 0x61, 0x33, 0x47, 0x61];
        payload.splice(5..5+imsi.len(), imsi);
        payload[5] = 1;  // & 7 == 1
        payload[0x5e2] = 3;  // MncLength == 3
        let rai = vec![0xaa, 0xaa, 0xaa];
        payload.splice(0x576..0x576+rai.len(), rai);
        sim_mm_read_all_mm_data_rsp.push_payload_field(QItemPDU::array_from_vec(payload));

        // prepare lte_rrc_cell_ind
        let mut lte_rrc_cell_ind = QItem::from_qid(0xf, 0x18, 0x3c75);
        let mut payload = vec![0; 0x2010];
        let one: u32 = 1;
        payload.splice(4..4+4, one.to_le_bytes());
        lte_rrc_cell_ind.push_payload_field(QItemPDU::array_from_vec(payload));

        // prepare lte_rrc_est_cnf
        let mut lte_rrc_est_cnf = QItem::from_qid(0xf, 0x18, 0x3c77);
        let payload = vec![0; 0x2010];
        lte_rrc_est_cnf.push_payload_field(QItemPDU::array_from_vec(payload));

        // lte_rrc_data_ind
        let mut lte_rrc_data_ind = QItem::from_qid(0xf, 0x18, 0x3c7b);
        let zero: u32 = 0;
        lte_rrc_data_ind.push_payload_field(QItemPDU::array_from_vec(zero.to_le_bytes().to_vec()));
        let ded_info_nas = self.gg.generate_example(state);
        lte_rrc_data_ind.push_payload_field(QItemPDU::indir_u32_from_grammar(ded_info_nas));

        // mm_rrc_data_ind
        let ded_info_nas = self.gg.generate_example(state);
        let payload = SmpfEventPaylod::GrammarInput(ded_info_nas);
        let mm_rrc_data_ind = SmpfEvent::new(0x4c10040, 0x7feffc00, payload);

        let ex = LorisInput {
            vendor_input: VendorInput::ShannonInput(
                // ShannonInput::Sael3Input(vec![lte_rrc_data_ind])
                ShannonInput::NasotInput(vec![mm_rrc_data_ind])
            ),
        };
        ex
    }

    pub fn regenerate_grammar_fields(&self, state: &mut S, input: &mut LorisInput) {
        match &mut input.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        for qitem in sael3_input.iter_mut() {
                            for pdu in qitem.payload.iter_mut() {
                                match pdu {
                                    QItemPDU::Array(field) | QItemPDU::IndirU32(field) => {
                                        match field {
                                            QItemField::GrammarInput(grammar) => {
                                                // let _ = std::mem::replace(grammar, self.gg.generate_example(state));
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ShannonInput::NasotInput(nasot_input) => {}
                }
            }
        };
    }

    pub fn generate_continue(&self, input: &mut LorisInput, state: &mut S) {
        match &mut input.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        for qitem in sael3_input.iter_mut() {
                            for pdu in qitem.payload.iter_mut() {
                                match pdu {
                                    QItemPDU::Array(field) | QItemPDU::IndirU32(field) => {
                                        match field {
                                            QItemField::GrammarInput(grammar_input) => {
                                                self.gg.generate_continue(grammar_input, state);
                                            },
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ShannonInput::NasotInput(nasot_input) => {
                        for event in nasot_input.iter_mut() {
                            match event.payload_mut() {
                                SmpfEventPaylod::GrammarInput(grammar_input) => {
                                    self.gg.generate_continue(grammar_input, state);
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}
