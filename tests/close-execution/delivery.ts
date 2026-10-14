import {
    bit,
    type CloseEnvelope,
    type CloseIntent,
    type CloseProposal,
    type CloseResponse,
} from '#tests/close-contract-model.js';

export type Message =
    | Readonly<{ kind: 'envelope'; envelope: CloseEnvelope }>
    | Readonly<{ kind: 'body'; envelope: CloseEnvelope }>
    | Readonly<{ kind: 'intent'; intent: CloseIntent }>
    | Readonly<{ kind: 'response'; response: CloseResponse }>
    | Readonly<{ kind: 'proposal'; proposal: CloseProposal }>
    // The honest organizer's copies of every named response, every envelope
    // they list and every usable slot's body.
    | Readonly<{ kind: 'closure'; proposal: CloseProposal }>
    // A responder's copy of a body it lists alone, for the organizer.
    | Readonly<{ kind: 'forward'; envelope: CloseEnvelope }>
    | Readonly<{
          kind: 'signature';
          signer: number;
          proposal: CloseProposal;
      }>
    | Readonly<{ kind: 'share'; signer: number; target: string }>;

export type Delivery = Readonly<{
    recipient: number;
    message: Message;
    action: number;
}>;

export class CloseDeliveryQueue {
    private pending: Delivery[] = [];
    private withheld: Delivery[] = [];
    step = 0;
    certified = false;
    constructor(
        private readonly recipients: ReadonlySet<number>,
        private readonly random: (bound: number) => number,
        private readonly isolated: number,
        private readonly priorityRecipient: number | undefined,
        private readonly action: number,
    ) {}
    get pendingCount() {
        return this.pending.length;
    }
    get hasWithheld() {
        return this.withheld.length > 0;
    }
    advance() {
        this.step += 1;
    }
    enqueue(...deliveries: Delivery[]) {
        this.pending.push(...deliveries);
    }
    withhold(delivery: Delivery) {
        this.withheld.push(delivery);
    }
    releaseWithheld() {
        this.pending.push(...this.withheld);
        this.withheld = [];
    }
    certify() {
        if (this.certified) return false;
        this.certified = true;
        this.releaseWithheld();
        return true;
    }
    send(message: Message, from: number | undefined) {
        const withhold =
            from !== undefined &&
            (this.isolated & bit(from)) !== 0 &&
            !this.certified;
        for (const recipient of this.recipients) {
            if (recipient === from) continue;
            const delivery = { recipient, message, action: this.action };
            if (withhold) this.withhold(delivery);
            else this.enqueue(delivery);
        }
    }
    sendTo(message: Message, from: number, recipient: number) {
        if (!this.recipients.has(recipient)) return;
        const delivery = { recipient, message, action: this.action };
        if ((this.isolated & bit(from)) !== 0 && !this.certified)
            this.withhold(delivery);
        else this.enqueue(delivery);
    }
    deliverNext(receive: (delivery: Delivery) => void) {
        const prioritized = this.pending.flatMap((delivery, index) =>
            delivery.recipient === this.priorityRecipient ? [index] : [],
        );
        const index =
            prioritized.length > 0
                ? prioritized[this.random(prioritized.length)]
                : this.random(this.pending.length);
        const [delivery] = this.pending.splice(index, 1);
        this.advance();
        receive(delivery);
        // Duplication follows delivery, including any certificate it created.
        if (this.random(10) === 0) this.pending.push(delivery);
    }
}
