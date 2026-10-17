use crate::{
    Error, Result, authentication,
    field::*,
    frontend::{self, Challenges},
    layout::Layout,
    reader::Reader,
    relation::Relation,
    require,
    statement::Statement,
    transcript::Transcript,
};

struct Switch {
    evaluation: Element,
    tail_weight: Element,
    batch: Element,
    private_evaluation: Element,
}
struct Stage {
    epsilon: Element,
    points: Vec<Element>,
    polynomials: Vec<Vec<Element>>,
    mask_target: Element,
    switch: Option<Switch>,
    positions: Vec<usize>,
    query_points: Vec<Element>,
}
struct Terminal {
    challenge: Element,
    target: Element,
    responses: Vec<Vec<Element>>,
    mask_positions: Vec<usize>,
}

fn respond(
    transcript: &mut Transcript<'_>,
    reader: &mut Reader<'_>,
    parts: &[&[u8]],
) -> Result<()> {
    transcript.respond(reader.take(128)?, parts);
    Ok(())
}

pub fn verify(
    role: &[u8],
    statement: &Statement,
    relation: &Relation,
    layout: &Layout,
    proof: &[u8],
) -> Result<()> {
    require(proof.len() <= layout.maximum_proof_bytes, Error::Encoding)?;
    let mut reader = Reader::new(proof);
    require(reader.take(4)? == b"CWP1", Error::Encoding)?;
    require(reader.digest()? == layout.context, Error::Context)?;
    let mut transcript = Transcript::new(role, &layout.context, layout.word_bytes);
    let mut roots = Vec::new();
    roots.push(reader.digest()?);
    respond(&mut transcript, &mut reader, &[&roots[0]])?;
    let lookup = transcript.challenge(0, true);
    roots.push(reader.digest()?);
    let mask_sum = reader.field()?;
    respond(
        &mut transcript,
        &mut reader,
        &[&roots[1], &encode(mask_sum)],
    )?;
    let lookup_weight = transcript.challenge(0, false);
    let affine = transcript.challenge(1, false);
    let combination = transcript.challenge(2, false);
    roots.push(reader.digest()?);
    respond(&mut transcript, &mut reader, &[&roots[2]])?;
    let point = transcript.challenge(0, true);
    let evaluations = reader.fields(layout.evaluations)?;
    respond(
        &mut transcript,
        &mut reader,
        &[&encode_fields(&evaluations)],
    )?;
    let evaluation_batch = transcript.challenge(0, false);
    let challenges = Challenges {
        lookup,
        lookup_weight,
        affine,
        combination,
        point,
    };
    let plan = &layout.plan;
    let mut stages = Vec::new();
    let mut terminal = None;
    for stage in 0..plan.domains.len() {
        let mask_root = reader.digest()?;
        roots.push(mask_root);
        let mask_target = reader.field()?;
        respond(
            &mut transcript,
            &mut reader,
            &[&mask_root, &encode(mask_target)],
        )?;
        let epsilon = transcript.challenge(0, false);
        let mut points = Vec::new();
        let mut polynomials = Vec::new();
        for _ in 0..plan.folds[stage] {
            let polynomial = reader.fields(layout.mask_length)?;
            respond(&mut transcript, &mut reader, &[&encode_fields(&polynomial)])?;
            polynomials.push(polynomial);
            points.push(transcript.challenge(0, false));
        }
        let (switch, positions) = if stage + 1 < plan.domains.len() {
            let next = reader.digest()?;
            let source = reader.digest()?;
            roots.extend([next, source]);
            respond(&mut transcript, &mut reader, &[&next, &source])?;
            let evaluation = transcript.challenge(0, false);
            let tail_weight = transcript.challenge(1, true);
            let private_evaluation = reader.field()?;
            respond(&mut transcript, &mut reader, &[&encode(private_evaluation)])?;
            let batch = transcript.challenge(0, false);
            (
                Some(Switch {
                    evaluation,
                    tail_weight,
                    batch,
                    private_evaluation,
                }),
                transcript.positions(96, plan.queries, plan.domains[stage]),
            )
        } else {
            let fresh_data = reader.digest()?;
            let fresh_masks = reader.digest()?;
            roots.extend([fresh_data, fresh_masks]);
            let target = reader.field()?;
            respond(
                &mut transcript,
                &mut reader,
                &[&fresh_data, &fresh_masks, &encode(target)],
            )?;
            let challenge = transcript.challenge(0, false);
            let mut responses = Vec::new();
            responses.push(reader.fields(plan.messages[stage] + plan.queries)?);
            for _ in 0..plan.masks {
                responses.push(reader.fields(layout.mask_length + plan.queries)?);
            }
            respond(
                &mut transcript,
                &mut reader,
                &[&encode_fields(
                    &responses.iter().flatten().copied().collect::<Vec<_>>(),
                )],
            )?;
            let positions = transcript.positions(0, plan.queries, plan.domains[stage]);
            let mask_positions =
                transcript.positions(4 * plan.queries, plan.queries, layout.mask_domain);
            terminal = Some(Terminal {
                challenge,
                target,
                responses,
                mask_positions,
            });
            (None, positions)
        };
        let query_points = code_points(plan.domains[stage], &positions);
        stages.push(Stage {
            epsilon,
            points,
            polynomials,
            mask_target,
            switch,
            positions,
            query_points,
        });
    }
    assert_eq!(transcript.round, plan.rounds + 4);
    assert_eq!(roots.len(), layout.trees.len());
    let terminal = terminal.unwrap();
    let mut authenticated = Vec::new();
    for tree in &layout.trees {
        let positions = if tree.mask {
            &terminal.mask_positions
        } else {
            &stages[tree.stage].positions
        };
        authenticated.push(authentication::opening(
            role,
            tree,
            &roots[tree.identifier],
            positions,
            &mut reader,
        )?);
    }
    reader.finish()?;

    // No public source calculation runs until every opening is authenticated.
    let (groups, mut target) = frontend::check(
        statement,
        relation,
        &challenges,
        mask_sum,
        &evaluations,
        evaluation_batch,
    )?;
    let mut forms = pack(&groups, plan.messages[0]);
    let mut mask_forms: Vec<Vec<Element>> = Vec::new();
    let mut mask_answers = vec![Vec::new(); plan.masks];
    for tree in &layout.trees {
        if let Some(offset) = tree.mask_offset {
            for (index, answers) in authenticated[tree.identifier].iter().enumerate() {
                mask_answers[offset + index] = answers.clone();
            }
        }
    }
    for (index, stage) in stages.iter().enumerate() {
        assert_eq!(forms.len(), plan.rows[index]);
        target = add(multiply(stage.epsilon, target), stage.mask_target);
        for (polynomial, &point) in stage.polynomials.iter().zip(&stage.points) {
            require(
                add(polynomial[0], polynomial.iter().copied().fold(ZERO, add)) == target,
                Error::Sumcheck,
            )?;
            target = evaluate(polynomial, point);
        }
        let mut form = fold(&forms, &stage.points);
        for value in &mut form {
            *value = multiply(stage.epsilon, *value);
        }
        // Each carried mask appears in all Boolean summands. Its form therefore
        // receives epsilon / 2^k, including after a code switch.
        let old_scale = scale(
            stage.epsilon,
            base::power(1 << stage.points.len(), MODULUS - 2),
        );
        for value in mask_forms.iter_mut().flatten() {
            *value = multiply(old_scale, *value);
        }
        mask_forms.extend(
            stage
                .points
                .iter()
                .map(|&point| powers(point, layout.mask_length)),
        );
        let data_answers = if index == 0 {
            authenticated[..3].concat()
        } else {
            authenticated[3 * index + 1].clone()
        };
        let answers = fold(&data_answers, &stage.points);
        if let Some(switch) = &stage.switch {
            let weights = powers(switch.batch, plan.queries + 2);
            let mut combined: Vec<_> = powers(switch.evaluation, form.len() + plan.queries)
                .into_iter()
                .map(|value| multiply(weights[1], value))
                .collect();
            for (query, &point) in stage.query_points.iter().enumerate() {
                let mut power = ONE;
                for coefficient in &mut combined {
                    *coefficient = add(*coefficient, multiply(weights[query + 2], power));
                    power = multiply(power, point);
                }
            }
            for (coefficient, &additional) in form.iter_mut().zip(&combined) {
                *coefficient = add(*coefficient, additional);
            }
            let mut source_form = combined[form.len()..].to_vec();
            source_form.push(multiply(weights[1], switch.tail_weight));
            mask_forms.push(source_form);
            forms = pack(&[form], plan.messages[index + 1]);
            target = add(
                add(target, multiply(weights[1], switch.private_evaluation)),
                dot(&weights[2..], &answers),
            );
        } else {
            let mask_points = code_points(layout.mask_domain, &terminal.mask_positions);
            let mut claims = vec![form];
            claims.extend(mask_forms);
            let mut openings = vec![answers];
            openings.extend(mask_answers);
            let mut fresh = authenticated[3 * index + 4].clone();
            fresh.extend_from_slice(&authenticated[3 * index + 5]);
            let claimed = claims
                .iter()
                .zip(&terminal.responses)
                .fold(ZERO, |sum, (form, response)| {
                    add(sum, dot(form, &response[..form.len()]))
                });
            require(
                claimed == add(terminal.target, multiply(terminal.challenge, target)),
                Error::Opening,
            )?;
            for (row, response) in terminal.responses.iter().enumerate() {
                let points = if row == 0 {
                    &stage.query_points
                } else {
                    &mask_points
                };
                for (query, &point) in points.iter().enumerate() {
                    let value = response.iter().rev().fold(ZERO, |sum, &coefficient| {
                        add(scale(sum, point[0]), coefficient)
                    });
                    require(
                        value
                            == add(
                                fresh[row][query],
                                multiply(terminal.challenge, openings[row][query]),
                            ),
                        Error::Opening,
                    )?;
                }
            }
            return Ok(());
        }
    }
    unreachable!("Every compiled plan has a terminal stage")
}

fn pack(groups: &[Vec<Element>], length: usize) -> Vec<Vec<Element>> {
    groups
        .iter()
        .flat_map(|group| {
            group.chunks(length).map(|chunk| {
                let mut row = chunk.to_vec();
                row.resize(length, ZERO);
                row
            })
        })
        .collect()
}
fn fold(rows: &[Vec<Element>], points: &[Element]) -> Vec<Element> {
    let mut result = vec![ZERO; rows[0].len()];
    for (index, row) in rows.iter().enumerate() {
        let weight = points
            .iter()
            .enumerate()
            .fold(ONE, |weight, (bit, &point)| {
                multiply(
                    weight,
                    if index >> bit & 1 == 0 {
                        subtract(ONE, point)
                    } else {
                        point
                    },
                )
            });
        for (result, &value) in result.iter_mut().zip(row) {
            *result = add(*result, multiply(weight, value));
        }
    }
    result
}
