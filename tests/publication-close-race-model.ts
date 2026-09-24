// One ballot slot, authenticated messages, and separate honest local views.
// This models the rejected wait-for-READY-before-close rule solely to retain
// its delayed-delivery counterexample. It creates no protocol capability.
type Delivery = Readonly<{
    sender: number;
    recipient: number;
    kind: 'echo' | 'ready';
    echoCertificate?: readonly number[];
}>;

export const runPublicationCloseRaceModel = (
    participantCount: number,
    completeDeliveryBeforeClose: boolean,
): Readonly<{
    closeSigners: number;
    deliveredMessages: number;
    honestParticipants: number;
    readySigners: number;
    unresolvedReadyWaiters: number;
}> => {
    if (
        !Number.isInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20
    ) {
        throw new RangeError(
            'The publication experiment requires a supported roster.',
        );
    }
    const corruptCount = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptCount;
    const local = Array.from({ length: quorum }, () => ({
        echoes: new Set<number>(),
        readies: new Set<number>(),
        sentReady: false,
        closed: false,
    }));
    let network: Delivery[] = [];
    let deliveredMessages = 0;
    const broadcast = (
        sender: number,
        kind: Delivery['kind'],
        echoCertificate?: readonly number[],
    ): void => {
        for (let recipient = 0; recipient < quorum; recipient += 1) {
            network.push({
                sender,
                recipient,
                kind,
                ...(echoCertificate === undefined ? {} : { echoCertificate }),
            });
        }
    };
    const deliver = (message: Delivery): void => {
        const state = local[message.recipient];
        if (state === undefined)
            throw new Error('An honest recipient is absent.');
        deliveredMessages += 1;
        if (message.kind === 'echo') state.echoes.add(message.sender);
        else {
            const signers = new Set(message.echoCertificate);
            if (
                signers.size !== quorum ||
                [...signers].some((signer) => signer < 0 || signer >= quorum)
            ) {
                throw new Error(
                    'The model READY lacks its actual ECHO evidence.',
                );
            }
            for (const signer of signers) state.echoes.add(signer);
            state.readies.add(message.sender);
        }
        if (!state.closed && !state.sentReady && state.echoes.size >= quorum) {
            state.sentReady = true;
            broadcast(message.recipient, 'ready', [...state.echoes]);
        }
    };
    const drain = (): void => {
        for (let index = 0; index < network.length; index += 1) {
            const message = network[index];
            if (message === undefined)
                throw new Error('A queued message is absent.');
            deliver(message);
        }
        network = [];
    };
    const close = (): void => {
        for (const state of local) {
            if (!state.sentReady || state.readies.size >= quorum)
                state.closed = true;
        }
    };
    for (let sender = 0; sender < quorum; sender += 1)
        broadcast(sender, 'echo');
    if (completeDeliveryBeforeClose) drain();
    else {
        const firstView = network.filter(({ recipient }) => recipient === 0);
        network = network.filter(({ recipient }) => recipient !== 0);
        firstView.forEach(deliver);
    }
    close();
    drain();
    close();
    return {
        closeSigners: local.filter(({ closed }) => closed).length,
        deliveredMessages,
        honestParticipants: quorum,
        readySigners: local.filter(({ sentReady }) => sentReady).length,
        unresolvedReadyWaiters: local.filter(
            ({ sentReady, readies }) => sentReady && readies.size < quorum,
        ).length,
    };
};
