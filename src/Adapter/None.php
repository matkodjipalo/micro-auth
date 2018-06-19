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

class None extends AbstractAdapter
{
    /**
     * Authenticate.
     */
    public function authenticate(ServerRequestInterface $request): ?array
    {
        return [];
    }

    /**
     * Get attributes.
     */
    public function getAttributes(IdentityInterface $identity): array
    {
        return [];
    }
}
