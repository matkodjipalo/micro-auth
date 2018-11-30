<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Adapter;

use Micro\Auth\IdentityInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AdapterInterface
{
    /**
     * Setup adapter.
     */
    public function setup(): AdapterInterface;

    /**
     * Authenticate.
     */
    public function authenticate(ServerRequestInterface $request): ?array;

    /**
     * Get attribute map.
     */
    public function getAttributeMap(): Iterable;

    /**
     * Get identity attributes.
     */
    public function getAttributes(IdentityInterface $identity): array;
}
